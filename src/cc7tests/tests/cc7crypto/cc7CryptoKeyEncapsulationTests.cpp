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

class cc7CryptoKeyEncapsulationTests : public UnitTest
{
public:
    cc7CryptoKeyEncapsulationTests()
    {
        CC7_REGISTER_TEST_METHOD(testEncapDecap);
    }
    
    // UNIT TESTS
    
    void testEncapDecap()
    {
        static const std::vector<std::string> test_data = {
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
        };
        for (const auto & alg : test_data) {
            auto kem = crypto::KeyEncapsulation::getInstance(alg);
            auto keys = kem->generate();
            auto enc_result = kem->encapsulate(keys->getPublicKey());
            auto wrapped_key = enc_result.first;
            auto bob_secret = enc_result.second;
            auto alice_secret = kem->decapsulate(keys->getPrivateKey(), wrapped_key);
            ccstAssertEqual(bob_secret->getKeyData(), alice_secret->getKeyData());
        }
    }

};

CC7_CREATE_UNIT_TEST(cc7CryptoKeyEncapsulationTests, "cc7")
    
} // cc7::tests
} // cc7
