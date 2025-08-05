/*
 * Copyright 2025 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cc7tests/CC7Tests.h>
#include <cc7/Time.h>

#include <thread>
#include <chrono>

using namespace std::chrono_literals;

namespace cc7
{
namespace tests
{

class TimeTests : public UnitTest
{
public:
    TimeTests()
    {
        CC7_REGISTER_TEST_METHOD(testElapsedTime);
        CC7_REGISTER_TEST_METHOD(testElapsedTimeMillis);
    }
    
    void testElapsedTime()
    {
        for (int i = 0; i < 10; i++) {
            auto t1 = GetCurrentTime();
            std::this_thread::sleep_for(10ms);
            auto t2 = GetCurrentTime();
            auto diff = t2 - t1;
            ccstAssertTrue(diff > 0.005);
            ccstAssertTrue(diff < 0.015);
        }
    }
    
    void testElapsedTimeMillis()
    {
        for (int i = 0; i < 10; i++) {
            auto t1 = GetCurrentTimeMillis();
            std::this_thread::sleep_for(10ms);
            auto t2 = GetCurrentTimeMillis();
            auto diff = t2 - t1;
            ccstAssertTrue(diff > 5);
            ccstAssertTrue(diff < 15);
        }
    }

};

CC7_CREATE_UNIT_TEST(TimeTests, "cc7")
    
} // cc7::tests
} // cc7
