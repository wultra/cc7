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

class KeyDerivationTests : public UnitTest
{
public:
    KeyDerivationTests()
    {
        CC7_REGISTER_TEST_METHOD(testKDF);
    }
    
    // UNIT TESTS
    
    void testKDF()
    {
        auto root = JSON_ParseFile(g_testFiles, "test-data/kdf-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & item : data) {
            // Load algorithm
            auto algorithm = item.stringAtPath("alg");
            // Iterate over all test vectors
            ccstMessage("%s", algorithm.c_str());
            
            auto && test_vectors = item.arrayAtPath("tests");
            for (const auto & test_data : test_vectors) {
                // create instance of MAC algorithm
                auto kdf = crypto::KeyDerivation::getInstance(algorithm);
                //
                auto key = test_data.dataFromHexStringAtPath("key");
                auto expected_dk = test_data.dataFromHexStringAtPath("dk");
                
                crypto::ParameterList params { { crypto::KDF_PARAM_KEY_SIZE, crypto::Parameter::take(expected_dk.size()) } };
                if (test_data.containsValueAtPath("info")) {
                    params[crypto::KDF_PARAM_INFO] = crypto::Parameter::copy(test_data.dataFromHexStringAtPath("info"));
                }
                if (test_data.containsValueAtPath("salt")) {
                    params[crypto::KDF_PARAM_SALT] = crypto::Parameter::copy(test_data.dataFromHexStringAtPath("salt"));
                }
                if (test_data.containsValueAtPath("iter")) {
                    params[crypto::KDF_PARAM_ITERATIONS] = crypto::Parameter::take((size_t)test_data.integerAtPath("iter"));
                }
                auto dk = kdf->deriveKeyBytes(key, params);
                ccstAssertEqual(expected_dk, dk);
                if (expected_dk != dk) {
                    ccstMessage("%s: dk   : %s", algorithm.c_str(), dk.hexString().c_str());
                    ccstMessage("%s: exp  : %s", algorithm.c_str(), expected_dk.hexString().c_str());
                }
            }
        }
    }

};

CC7_CREATE_UNIT_TEST(KeyDerivationTests, "cc7")
    
} // cc7::tests
} // cc7
