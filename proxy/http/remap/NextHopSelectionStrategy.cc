/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <yaml-cpp/yaml.h>
#include "I_Machine.h"
#include "NextHopSelectionStrategy.h"

constexpr const char *debug_tag = "next_hop";

// hash_key strings.
constexpr std::string_view hash_key_uri           = "uri";
constexpr std::string_view hash_key_url           = "url";
constexpr std::string_view hash_key_hostname      = "hostname";
constexpr std::string_view hash_key_path          = "path";
constexpr std::string_view hash_key_path_query    = "path+query";
constexpr std::string_view hash_key_path_fragment = "path+fragment";
constexpr std::string_view hash_key_cache         = "cache_key";

// protocol strings.
constexpr std::string_view http_protocol  = "http";
constexpr std::string_view https_protocol = "https";

// ring mode strings
constexpr std::string_view alternate_rings = "alternate_ring";
constexpr std::string_view exhaust_rings   = "exhaust_ring";

// health check strings
constexpr std::string_view active_health_check  = "active";
constexpr std::string_view passive_health_check = "passive";

constexpr const char *policy_strings[] = {"NH_UNDEFINED", "NH_FIRST_LIVE", "NH_RR_STRICT",
                                          "NH_RR_IP",     "NH_RR_LATCHED", "NH_CONSISTENT_HASH"};

NextHopSelectionStrategy::NextHopSelectionStrategy(const std::string_view &name, const NHPolicyType &policy)
{
  strategy_name = name;
  hash_key      = NH_PATH_HASH_KEY;
  policy_type   = policy;
  protocol      = NH_HTTP_PROTO;
  ring_mode     = NH_ALTERNATE_RING;
  groups        = 0;
  num_parents   = 0;
  NH_Debug(debug_tag, "Using a selection strategy of type %s", policy_strings[policy]);
}

//
// parse out the data for this strategy.
//
bool
NextHopSelectionStrategy::Init(const YAML::Node &n)
{
  NH_Debug("next_hop", "calling Init()");
  try {
    if (n["hash_key"]) {
      auto hash_key_val = n["hash_key"].Scalar();
      if (hash_key_val == hash_key_uri) {
        hash_key = NH_URI_HASH_KEY;
      } else if (hash_key_val == hash_key_url) {
        hash_key = NH_URL_HASH_KEY;
      } else if (hash_key_val == hash_key_hostname) {
        hash_key = NH_HOSTNAME_HASH_KEY;
      } else if (hash_key_val == hash_key_path) {
        hash_key = NH_PATH_HASH_KEY;
      } else if (hash_key_val == hash_key_path_query) {
        hash_key = NH_PATH_QUERY_HASH_KEY;
      } else if (hash_key_val == hash_key_path_fragment) {
        hash_key = NH_PATH_FRAGMENT_HASH_KEY;
      } else if (hash_key_val == hash_key_cache) {
        hash_key = NH_CACHE_HASH_KEY;
      } else {
        hash_key = NH_PATH_HASH_KEY;
        NH_Note("Invalid 'hash_key' value, '%s', for the strategy named '%s', using default '%s'.", hash_key_val.c_str(),
                strategy_name.c_str(), hash_key_path.data());
      }
    }

    if (n["protocol"]) {
      auto protocol_val = n["protocol"].Scalar();
      if (protocol_val == http_protocol) {
        protocol = NH_HTTP_PROTO;
      } else if (protocol_val == https_protocol) {
        protocol = NH_HTTPS_PROTO;
      } else {
        protocol = NH_HTTP_PROTO;
        NH_Note("Invalid 'protocol' value, '%s', for the strategy named '%s', usiing default '%s'.", protocol_val.c_str(),
                strategy_name.c_str(), http_protocol.data());
      }
    }

    // go_direct config.
    if (n["go_direct"]) {
      go_direct = n["go_direct"].as<bool>();
    }

    // parent_is_proxy config.
    if (n["parent_is_proxy"]) {
      parent_is_proxy = n["parent_is_proxy"].as<bool>();
    }

    // failover node.
    YAML::Node failover_node;
    if (n["failover"]) {
      failover_node = n["failover"];
      if (failover_node["ring_mode"]) {
        auto ring_mode_val = failover_node["ring_mode"].Scalar();
        if (ring_mode_val == alternate_rings) {
          ring_mode = NH_ALTERNATE_RING;
        } else if (ring_mode_val == exhaust_rings) {
          ring_mode = NH_EXHAUST_RING;
        } else {
          ring_mode = NH_ALTERNATE_RING;
          NH_Note("Invalid 'ring_mode' value, '%s', for the strategy named '%s', using default '%s'.", ring_mode_val.c_str(),
                  strategy_name.c_str(), alternate_rings.data());
        }
      }
      if (failover_node["max_simple_retries"]) {
        max_simple_retries = failover_node["max_simple_retries"].as<int>();
      }

      YAML::Node resp_codes_node;
      if (failover_node["response_codes"]) {
        resp_codes_node = failover_node["response_codes"];
        if (resp_codes_node.Type() != YAML::NodeType::Sequence) {
          NH_Error("Error in the response_codes definition for the strategy named '%s', skipping response_codes.",
                   strategy_name.c_str());
        } else {
          for (unsigned int k = 0; k < resp_codes_node.size(); ++k) {
            auto code = resp_codes_node[k].as<int>();
            if (code > 300 && code < 599) {
              resp_codes.add(code);
            } else {
              NH_Note("Skipping invalid response code '%d' for the strategy named '%s'.", code, strategy_name.c_str());
            }
          }
          resp_codes.sort();
        }
      }
      YAML::Node health_check_node;
      if (failover_node["health_check"]) {
        health_check_node = failover_node["health_check"];
        if (health_check_node.Type() != YAML::NodeType::Sequence) {
          NH_Error("Error in the health_check definition for the strategy named '%s', skipping health_checks.",
                   strategy_name.c_str());
        } else {
          for (auto it = health_check_node.begin(); it != health_check_node.end(); ++it) {
            auto health_check = it->as<std::string>();
            if (health_check.compare(active_health_check) == 0) {
              health_checks.active = true;
            }
            if (health_check.compare(passive_health_check) == 0) {
              health_checks.passive = true;
            }
          }
        }
      }
    }

    // parse and load the host data
    YAML::Node groups_node;
    if (n["groups"]) {
      groups_node = n["groups"];
      // a groups list is required.
      if (groups_node.Type() != YAML::NodeType::Sequence) {
        throw std::invalid_argument("Invalid groups definition, expected a sequence, '" + strategy_name + "' cannot be loaded.");
      } else {
        Machine *mach      = Machine::instance();
        HostStatus &h_stat = HostStatus::instance();
        uint32_t grp_size  = groups_node.size();
        if (grp_size > MAX_GROUP_RINGS) {
          NH_Note("the groups list exceeds the maximum of %d for the strategy '%s'. Only the first %d groups will be configured.",
                  MAX_GROUP_RINGS, strategy_name.c_str(), MAX_GROUP_RINGS);
          groups = MAX_GROUP_RINGS;
        } else {
          groups = groups_node.size();
        }
        // resize the hosts vector.
        hosts.reserve(groups);
        // loop through the groups
        for (unsigned int grp = 0; grp < groups; ++grp) {
          YAML::Node hosts_list = groups_node[grp];

          // a list of hosts is required.
          if (hosts_list.Type() != YAML::NodeType::Sequence) {
            throw std::invalid_argument("Invalid hosts definition, expected a sequence, '" + strategy_name + "' cannot be loaded.");
          } else {
            // loop through the hosts list.
            std::vector<std::shared_ptr<HostRecord>> hosts_inner;

            for (unsigned int hst = 0; hst < hosts_list.size(); ++hst) {
              std::shared_ptr<HostRecord> host_rec = std::make_shared<HostRecord>(hosts_list[hst].as<HostRecord>());
              host_rec->group_index                = grp;
              host_rec->host_index                 = hst;
              if (protocol == NH_HTTP_PROTO) {
                host_rec->scheme = http_protocol;
              } else if (protocol == NH_HTTPS_PROTO) {
                host_rec->scheme = https_protocol;
              }
              if (mach->is_self(host_rec->hostname.c_str())) {
                h_stat.setHostStatus(host_rec->hostname.c_str(), HostStatus_t::HOST_STATUS_DOWN, 0, Reason::SELF_DETECT);
              }
              hosts_inner.push_back(std::move(host_rec));
              num_parents++;
            }
            hosts.push_back(std::move(hosts_inner));
          }
        }
      }
    }
  } catch (std::exception &ex) {
    NH_Note("Error parsing the strategy named '%s' due to '%s', this strategy will be ignored.", strategy_name.c_str(), ex.what());
    return false;
  }

  return true;
}

void
NextHopSelectionStrategy::markNextHopDown(const uint64_t sm_id, ParentResult *result, const uint64_t fail_threshold,
                                          const uint64_t retry_time)
{
  time_t now              = 0;
  uint32_t new_fail_count = 0;

  //  Make sure that we are being called back with with a
  //  result structure with a selected parent.
  ink_assert(result->result == PARENT_SPECIFIED);
  if (result->result != PARENT_SPECIFIED) {
    return;
  }
  // If we were set through the API we currently have not failover
  //   so just return fail
  if (result->is_api_result()) {
    ink_assert(0);
    return;
  }
  uint32_t hst_size = hosts[result->last_group].size();
  ink_assert(result->last_parent < hst_size);
  std::shared_ptr<HostRecord> h = hosts[result->last_group][result->last_parent];

  // If the parent has already been marked down, just increment
  //   the failure count.  If this is the first mark down on a
  //   parent we need to both set the failure time and set
  //   count to one.  It's possible for the count and time get out
  //   sync due there being no locks.  Therefore the code should
  //   handle this condition.  If this was the result of a retry, we
  //   must update move the failedAt timestamp to now so that we continue
  //   negative cache the parent
  if (h->failedAt == 0 || result->retry == true) {
    { // lock_guard
      std::lock_guard<std::mutex> lock(h->_mutex);
      // Mark the parent failure time.
      h->failedAt = time(nullptr);

      // If this is clean mark down and not a failed retry, we
      //   must set the count to reflect this
      if (result->retry == false) {
        new_fail_count = h->failCount = 1;
      }
    }

    NH_Note("[%" PRId64 "] NextHop %s marked as down %s:%d", sm_id, (result->retry) ? "retry" : "initially", h->hostname.c_str(),
            h->getPort());

  } else {
    int old_count = 0;
    now           = time(nullptr);

    // if the last failure was outside the retry window, set the failcount to 1 and failedAt to now.
    if ((h->failedAt + retry_time) < static_cast<unsigned>(now)) {
      std::lock_guard<std::mutex> lock(h->_mutex);
      h->failCount = 1;
      h->failedAt  = now;
    } else {
      std::lock_guard<std::mutex> lock(h->_mutex);
      old_count = h->failCount++;
    }

    new_fail_count = old_count + 1;
    NH_Debug("parent_select", "[%" PRId64 "] Parent fail count increased to %d for %s:%d", sm_id, new_fail_count,
             h->hostname.c_str(), h->getPort());
  }

  if (new_fail_count > 0 && new_fail_count >= fail_threshold) {
    h->set_unavailable();
    NH_Note("[%" PRId64 "] Failure threshold met failcount:%d >= threshold:%ld, http parent proxy %s:%d marked down", sm_id,
            new_fail_count, fail_threshold, h->hostname.c_str(), h->getPort());
    NH_Debug("parent_select", "[%" PRId64 "] NextHop %s:%d marked unavailable, h->available=%s", sm_id, h->hostname.c_str(),
             h->getPort(), (h->available) ? "true" : "false");
  }
}

void
NextHopSelectionStrategy::markNextHopUp(const uint64_t sm_id, ParentResult *result)
{
  uint32_t old_count = 0;
  //  Make sure that we are being called back with with a
  //   result structure with a parent that is being retried
  ink_release_assert(result->retry == true);
  ink_assert(result->result == PARENT_SPECIFIED);
  if (result->result != PARENT_SPECIFIED) {
    return;
  }
  // If we were set through the API we currently have not failover
  //   so just return fail
  if (result->is_api_result()) {
    ink_assert(0);
    return;
  }
  uint32_t hst_size = hosts[result->last_group].size();
  ink_assert(result->last_parent < hst_size);
  std::shared_ptr<HostRecord> h = hosts[result->last_group][result->last_parent];

  if (!h->available) {
    h->set_available();
  }
  if (h->available && old_count > 0) {
    NH_Note("[%" PRId64 "] http parent proxy %s:%d restored", sm_id, h->hostname.c_str(), h->getPort());
  }
}

namespace YAML
{
template <> struct convert<HostRecord> {
  static bool
  decode(const Node &node, HostRecord &nh)
  {
    YAML::Node nd;
    bool merge_tag_used = false;

    // check for YAML merge tag.
    if (node["<<"]) {
      nd             = node["<<"];
      merge_tag_used = true;
    } else {
      nd = node;
    }

    // lookup the hostname
    if (nd["host"]) {
      nh.hostname = nd["host"].Scalar();
    } else {
      throw std::invalid_argument("Invalid host defintion, missing host name.");
    }

    // lookup the port numbers supported by this host.
    YAML::Node proto;
    if ((proto = nd["protocol"])) {
      if (proto.Type() != YAML::NodeType::Sequence) {
        throw std::invalid_argument("Invalid host protocol defintion, expected a sequence.");
      } else {
        for (unsigned int i = 0; i < proto.size(); i++) {
          YAML::Node scheme_port = proto[i];
          if (scheme_port["http"]) {
            nh.http_port = scheme_port["http"].as<int>();
          }
          if (scheme_port["https"]) {
            nh.https_port = scheme_port["https"].as<int>();
          }
        }
      }
    } else { // use default ports.
      NH_Note("No protocol ports are defined for the host '%s', using defaults http: 80 and https: 443", nh.hostname.data());
      nh.http_port  = 80;
      nh.https_port = 443;
    }

    // get the host's weight
    YAML::Node weight;
    if (merge_tag_used) {
      weight    = node["weight"];
      nh.weight = weight.as<float>();
    } else if ((weight = nd["weight"])) {
      nh.weight = weight.as<float>();
    } else {
      NH_Note("No weight is defined for the host '%s', using default 1.0", nh.hostname.data());
      nh.weight = 1.0;
    }

    // get the host's optional hash_string
    YAML::Node hash;
    if ((hash = nd["hash_string"])) {
      nh.hash_string = hash.Scalar();
    }

    return true;
  }
};
} // namespace YAML
