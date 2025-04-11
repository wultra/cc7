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
#include <cc7/crypto/Crypto.h>
#include <cc7tests/JSONReader.h>
#include <cc7tests/TestDirectory.h>

namespace cc7
{
namespace tests
{
extern TestDirectory g_testFiles;

class cc7CryptoMessageDigestTests : public UnitTest
{
public:
    cc7CryptoMessageDigestTests()
    {
        CC7_REGISTER_TEST_METHOD(testMessageDigest);
    }
    
    // UNIT TESTS
    
    void testMessageDigest()
    {
        auto root = JSON_ParseFile(g_testFiles, "test-data/md-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & item : data) {
            // Load algorithm
            auto algorithm = item.stringAtPath("alg");
            // Iterate over all test vectors
            auto && test_vectors = item.arrayAtPath("tests");
            for (const auto & test_data : test_vectors) {
                // create instance of MAC algorithm
                auto md = crypto::MessageDigest::getInstance(algorithm);
                //
                auto message = test_data.dataFromHexStringAtPath("message");
                auto expected_hash = test_data.dataFromHexStringAtPath("hash");
                auto hash = md->digest(message);
                ccstAssertEqual(expected_hash, hash);
            }
        }
    }

};

CC7_CREATE_UNIT_TEST(cc7CryptoMessageDigestTests, "cc7")
    
} // cc7::tests
} // cc7
