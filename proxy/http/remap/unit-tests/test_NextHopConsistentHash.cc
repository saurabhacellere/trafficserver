/** @file

  Unit tests for the NextHopConsistentHash.

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

  @section details Details

  Unit testing the NextHopConsistentHash class.

 */

#define CATCH_CONFIG_MAIN /* include main function */

#include <catch.hpp> /* catch unit-test framework */
#include <yaml-cpp/yaml.h>

#include "nexthop_test_stubs.h"
#include "NextHopSelectionStrategy.h"
#include "NextHopStrategyFactory.h"
#include "NextHopConsistentHash.h"

#include "HTTP.h"
extern int cmd_disable_pfreelist;

SCENARIO("Testing NextHopConsistentHash class, using policy 'consistent_hash'", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in br();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  std::shared_ptr<NextHopSelectionStrategy> strategy;
  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    NextHopStrategyFactory nhf("unit-tests/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("consistent-hash-1");

    WHEN("the config is loaded.")
    {
      uint64_t fail_threshold = 1;
      uint64_t retry_time     = 1;
      TestData rdata;
      rdata.xact_start = time(nullptr);
      HttpRequestData request;
      ParentResult result;
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);

        // first request.
        br(&request, "rabbit.net");
        result.reset();
        strategy->findNextHop(10001, &result, &request, fail_threshold, retry_time);
        THEN("verify the first request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "p1.foo.com") == 0);
        }
        strategy->markNextHopDown(10001, &result, 1, fail_threshold);
        // second request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10002, &result, &request, fail_threshold, retry_time);
        THEN("verify the second request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "p2.foo.com") == 0);
        }
        strategy->markNextHopDown(10002, &result, 1, fail_threshold);
        // third request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10003, &result, &request, fail_threshold, retry_time);
        THEN("verify the third request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "s2.bar.com") == 0);
        }
        strategy->markNextHopDown(10003, &result, 1, fail_threshold);
        // fourth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10004, &result, &request, fail_threshold, retry_time);
        THEN("verify the fourth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "s1.bar.com") == 0);
        }
        strategy->markNextHopDown(10004, &result, 1, fail_threshold);
        // fifth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10005, &result, &request, fail_threshold, retry_time);
        THEN("verify the fifth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "q1.bar.com") == 0);
        }
        strategy->markNextHopDown(10005, &result, 1, fail_threshold);
        // sixth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10006, &result, &request, fail_threshold, retry_time);
        THEN("verify the sixth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "q2.bar.com") == 0);
        }
        strategy->markNextHopDown(10006, &result, 1, fail_threshold);
        // seventh request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10007, &result, &request, fail_threshold, retry_time);
        THEN("verify the seventh request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_DIRECT);
          REQUIRE(result.hostname == nullptr);
        }

        // sleep and test that q2 is becomes retryable;
        sleep(3);
        // eighth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        br(&request, "rabbit.net");
        strategy->findNextHop(10008, &result, &request, fail_threshold, retry_time);
        THEN("verify the eighth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "q2.bar.com") == 0);
        }
      }
    }
  }
}

SCENARIO("Testing NextHopConsistentHash class (all firstcalls), using policy 'consistent_hash'", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in br();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  std::shared_ptr<NextHopSelectionStrategy> strategy;
  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    NextHopStrategyFactory nhf("unit-tests/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("consistent-hash-1");

    WHEN("the config is loaded.")
    {
      uint64_t fail_threshold = 1;
      uint64_t retry_time     = 1;
      TestData rdata;
      rdata.xact_start = time(nullptr);
      HttpRequestData request;
      ParentResult result;
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);

        // first request.
        br(&request, "rabbit.net");
        result.reset();
        strategy->findNextHop(20001, &result, &request, fail_threshold, retry_time);
        THEN("verify the first request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "p1.foo.com") == 0);
        }
        strategy->markNextHopDown(20001, &result, 1, fail_threshold);
        // second request
        br(&request, "rabbit.net");
        result.reset();
        strategy->findNextHop(20002, &result, &request, fail_threshold, retry_time);
        THEN("verify the second request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "p2.foo.com") == 0);
        }
        strategy->markNextHopDown(20002, &result, 1, fail_threshold);
        // third request
        br(&request, "rabbit.net");
        result.reset();
        strategy->findNextHop(20003, &result, &request, fail_threshold, retry_time);
        THEN("verify the third request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "s2.bar.com") == 0);
        }
        strategy->markNextHopDown(20003, &result, 1, fail_threshold);
        // fourth request
        br(&request, "rabbit.net");
        result.reset();
        strategy->findNextHop(20004, &result, &request, fail_threshold, retry_time);
        THEN("verify the fourth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "q1.bar.com") == 0);
        }
        strategy->markNextHopDown(20004, &result, 1, fail_threshold);
        // fifth request
        br(&request, "rabbit.net/asset1");
        result.reset();
        strategy->findNextHop(20005, &result, &request, fail_threshold, retry_time);
        THEN("verify the fifth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_DIRECT);
          REQUIRE(result.hostname == nullptr);
        }
        // sixth request - wait and p1 should now become available
        sleep(2);
        br(&request, "rabbit.net");
        result.reset();
        strategy->findNextHop(20006, &result, &request, fail_threshold, retry_time);
        THEN("verify the sixth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "p1.foo.com") == 0);
        }
      }
    }
  }
}

SCENARIO("Testing NextHopConsistentHash class (alternating rings), using policy 'consistent_hash'", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in br();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  std::shared_ptr<NextHopSelectionStrategy> strategy;
  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    NextHopStrategyFactory nhf("unit-tests/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("consistent-hash-2");

    WHEN("the config is loaded.")
    {
      uint64_t fail_threshold = 1;
      uint64_t retry_time     = 1;
      TestData rdata;
      rdata.xact_start = time(nullptr);
      HttpRequestData request;
      ParentResult result;
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);

        // first request.
        br(&request, "bunny.net/asset1");
        result.reset();
        strategy->findNextHop(30001, &result, &request, fail_threshold, retry_time);
        THEN("verify the first request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c2.foo.com") == 0);
        }
        // simulated failure, mark c2 down and retry request
        strategy->markNextHopDown(30001, &result, 1, fail_threshold);
        // second request
        br(&request, "bunny.net.net/asset1");
        strategy->findNextHop(30002, &result, &request, fail_threshold, retry_time);
        THEN("verify the second request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c3.bar.com") == 0);
        }
        // just mark it down
        strategy->markNextHopDown(30002, &result, 1, fail_threshold);
        // third request
        br(&request, "bunny.net/asset2");
        result.reset();
        // just mark it down.
        strategy->findNextHop(30003, &result, &request, fail_threshold, retry_time);
        THEN("verify the third request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c6.bar.com") == 0);
        }
        // just mark it down and retry request
        strategy->markNextHopDown(30003, &result, 1, fail_threshold);
        // fourth request
        br(&request, "bunny.net/asset2");
        strategy->findNextHop(30004, &result, &request, fail_threshold, retry_time);
        THEN("verify the fourth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c1.foo.com") == 0);
        }
        // mark it down
        strategy->markNextHopDown(30004, &result, 1, fail_threshold);
        // fifth request - new request
        br(&request, "bunny.net/asset3");
        result.reset();
        strategy->findNextHop(30005, &result, &request, fail_threshold, retry_time);
        THEN("verify the fifth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c4.bar.com") == 0);
        }
        // mark it down and retry
        strategy->markNextHopDown(30005, &result, 1, fail_threshold);
        // sixth request
        br(&request, "bunny.net/asset3");
        result.reset();
        strategy->findNextHop(30006, &result, &request, fail_threshold, retry_time);
        THEN("verify the sixth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c5.bar.com") == 0);
        }
        // mark it down
        strategy->markNextHopDown(30006, &result, 1, fail_threshold);
        // seventh request - new request with all hosts down and go_direct is false.
        br(&request, "bunny.net/asset4");
        result.reset();
        strategy->findNextHop(30007, &result, &request, fail_threshold, retry_time);
        THEN("verify the seventh request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_FAIL);
          REQUIRE(result.hostname == nullptr);
        }
        // eighth request - retry after waiting for the retry window to expire.
        sleep(2);
        br(&request, "bunny.net/asset4");
        result.reset();
        strategy->findNextHop(30008, &result, &request, fail_threshold, retry_time);
        THEN("verify the eighth request.")
        {
          REQUIRE(result.result == ParentResultType::PARENT_SPECIFIED);
          REQUIRE(strcmp(result.hostname, "c2.foo.com") == 0);
        }
      }
    }
  }
}
