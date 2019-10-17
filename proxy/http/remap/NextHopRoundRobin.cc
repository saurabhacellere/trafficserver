/** @file

  Implementation of various round robin nexthop selections strategies.

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

#include <mutex>
#include <yaml-cpp/yaml.h>

#include "NextHopRoundRobin.h"

NextHopRoundRobin::~NextHopRoundRobin()
{
  NH_Debug("next_hop", "destructor called for strategy named: %s", strategy_name.c_str());
}

void
NextHopRoundRobin::findNextHop(const uint64_t sm_id, ParentResult *result, RequestData *rdata, const uint64_t fail_threshold,
                               const uint64_t retry_time)
{
  bool firstcall         = true;
  bool parentUp          = false;
  bool parentRetry       = false;
  bool wrapped           = result->wrap_around;
  uint32_t cur_hst_index = 0;
  uint32_t cur_grp_index = 0;
  uint32_t hst_size      = hosts[cur_grp_index].size();
  std::shared_ptr<HostRecord> cur_host;
  HostStatus &pStatus           = HostStatus::instance();
  HttpRequestData *request_info = static_cast<HttpRequestData *>(rdata);
  HostStatus_t host_stat        = HostStatus_t::HOST_STATUS_UP;

  if (result->line_number != -1 && result->result != PARENT_UNDEFINED) {
    firstcall = false;
  }

  if (firstcall) {
    // distance is the index into the strategies map, this is the equivalent to the old line_number in parent.config.
    result->line_number = distance;
    NH_Debug("next_hop", "[%" PRId64 "] first call , cur_grp_index: %d, cur_hst_index: %d, distance: %d", sm_id, cur_grp_index,
             cur_hst_index, distance);
    switch (policy_type) {
    case NH_FIRST_LIVE:
      result->start_parent = cur_hst_index = 0;
      cur_grp_index                        = 0;
      break;
    case NH_RR_STRICT: {
      std::lock_guard<std::mutex> lock(_mutex);
      cur_hst_index = result->start_parent = this->hst_index;
      cur_grp_index                        = 0;
      this->hst_index                      = (this->hst_index + 1) % hst_size;
    } break;
    case NH_RR_IP:
      cur_grp_index = 0;
      if (rdata->get_client_ip() != nullptr) {
        cur_hst_index = result->start_parent = ntohl(ats_ip_hash(rdata->get_client_ip())) % hst_size;
      } else {
        cur_hst_index = this->hst_index;
      }
      break;
    case NH_RR_LATCHED:
      cur_grp_index = 0;
      cur_hst_index = result->start_parent = latched_index;
      break;
    default:
      ink_release_assert(0);
      break;
    }
    cur_host = hosts[cur_grp_index][cur_hst_index];
    NH_Debug("next_hop", "[%" PRId64 "] first call, cur_grp_index: %d, cur_hst_index: %d", sm_id, cur_grp_index, cur_hst_index);
  } else {
    NH_Debug("next_hop", "[%" PRId64 "] next call, cur_grp_index: %d, cur_hst_index: %d, distance: %d", sm_id, cur_grp_index,
             cur_hst_index, distance);
    // Move to next parent due to failure
    latched_index = cur_hst_index = (result->last_parent + 1) % hst_size;
    cur_host                      = hosts[cur_grp_index][cur_hst_index];

    // Check to see if we have wrapped around
    if (static_cast<unsigned int>(cur_hst_index) == result->start_parent) {
      // We've wrapped around so bypass if we can
      if (go_direct == true) {
        result->result = PARENT_DIRECT;
      } else {
        result->result = PARENT_FAIL;
      }
      result->hostname    = nullptr;
      result->port        = 0;
      result->wrap_around = true;
      return;
    }
  }

  // Loop through the array of parent seeing if any are up or
  //   should be retried
  do {
    HostStatRec *hst = pStatus.getHostStatus(cur_host->hostname.c_str());
    host_stat        = (hst) ? hst->status : HostStatus_t::HOST_STATUS_UP;
    // if the config ignore_self_detect is set to true and the host is down due to SELF_DETECT reason
    // ignore the down status and mark it as avaialble
    if (ignore_self_detect && (hst && hst->status == HOST_STATUS_DOWN)) {
      if (hst->reasons == Reason::SELF_DETECT) {
        host_stat = HOST_STATUS_UP;
      }
    }
    // DNS ParentOnly inhibits bypassing the parent so always return that
    NH_Debug("next_hop",
             "[%" PRId64
             "] Selected a parent, %s,  failCount (faileAt: %d failCount: %d), FailThreshold: %ld, request_info->xact_start: %ld",
             sm_id, cur_host->hostname.c_str(), (unsigned)cur_host->failedAt, cur_host->failCount, fail_threshold,
             request_info->xact_start);
    if ((cur_host->failedAt == 0) || (cur_host->failCount < fail_threshold)) {
      if (host_stat == HOST_STATUS_UP) {
        NH_Debug("next_hop",
                 "[%" PRId64 "] Selecting a parent, %s,  due to little failCount (faileAt: %d failCount: %d), FailThreshold: %ld",
                 sm_id, cur_host->hostname.c_str(), (unsigned)cur_host->failedAt, cur_host->failCount, fail_threshold);
        parentUp = true;
      }
    } else {
      if (((result->wrap_around) || (cur_host->failedAt + retry_time) < static_cast<unsigned>(request_info->xact_start)) &&
          host_stat == HOST_STATUS_UP) {
        // Reuse the parent
        parentUp    = true;
        parentRetry = true;
        NH_Debug("next_hop", "[%" PRId64 "]  NextHop marked for retry %s:%d", sm_id, cur_host->hostname.c_str(),
                 hosts[cur_grp_index][cur_hst_index]->getPort());
      } else {
        parentUp = false;
      }
    }
    NH_Debug("next_hop", "[%" PRId64 "] parentUp: %s, hostname: %s, host status: %s", sm_id, parentUp ? "true" : "false",
             cur_host->hostname.c_str(), HostStatusNames[host_stat]);

    if (parentUp == true && host_stat != HOST_STATUS_DOWN) {
      NH_Debug("next_hop", "[%" PRId64 "] status for %s: %s", sm_id, cur_host->hostname.c_str(), HostStatusNames[host_stat]);
      result->result      = PARENT_SPECIFIED;
      result->hostname    = cur_host->hostname.c_str();
      result->port        = cur_host->getPort();
      result->last_parent = cur_hst_index;
      result->last_group  = cur_grp_index;
      result->retry       = parentRetry;
      ink_assert(result->hostname != nullptr);
      ink_assert(result->port != 0);
      NH_Debug("next_hop", "[%" PRId64 "] Chosen parent = %s.%d", sm_id, result->hostname, result->port);
      return;
    }

    if (ring_mode == NH_ALTERNATE_RING) {
      if (groups > 1) {
        cur_grp_index = (cur_grp_index + 1) % groups;
      }
    } else { // NH_EXHAUST_RING
      latched_index = cur_hst_index = (cur_hst_index + 1) % hst_size;
      if (groups > 1 && cur_hst_index == 0) {
        cur_grp_index = (cur_grp_index + 1) % groups;
        hst_size      = hosts[cur_grp_index].size();
        if (cur_grp_index == 0) {
          wrapped = result->wrap_around = true;
        }
      }
    }
    cur_host = hosts[cur_grp_index][cur_hst_index];
  } while (!wrapped);

  if (go_direct == true) {
    result->result = PARENT_DIRECT;
  } else {
    result->result = PARENT_FAIL;
  }

  result->hostname = nullptr;
  result->port     = 0;
}
