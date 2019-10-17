/** @file

  Implementation of nexthop consistent hash selections strategies.

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

#pragma once

#include <map>
#include <vector>
#include "NextHopSelectionStrategy.h"

class NextHopConsistentHash : public NextHopSelectionStrategy
{
  std::vector<std::shared_ptr<ATSConsistentHash>> rings;

  uint64_t getHashKey(uint64_t sm_id, HttpRequestData *hrdata, ATSHash64 *h);

public:
  NextHopConsistentHash() = delete;
  NextHopConsistentHash(const std::string_view name, const NHPolicyType &policy) : NextHopSelectionStrategy(name, policy) {}
  ~NextHopConsistentHash();
  bool Init(const YAML::Node &n);
  void findNextHop(const uint64_t sm_id, ParentResult *result, RequestData *rdata, const uint64_t fail_threshold,
                   const uint64_t retry_time) override;
};
