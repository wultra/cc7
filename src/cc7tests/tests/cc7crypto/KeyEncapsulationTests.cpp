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
#include <cc7tests/TestDirectory.h>
#include <cc7/CC7.h>

namespace cc7
{
namespace tests
{
extern TestDirectory g_testFiles;

class KeyEncapsulationTests : public UnitTest
{
public:
    KeyEncapsulationTests()
    {
        CC7_REGISTER_TEST_METHOD(testEncapDecap);
        CC7_REGISTER_TEST_METHOD(testMLKEM);
        //CC7_REGISTER_TEST_METHOD(generateMLKEM);
    }
    
    // UNIT TESTS
    
    void testsWithKeyPair(const crypto::KeyPairPtr & keys, const crypto::KeyEncapsulationPtr & kem, const cc7::crypto::KeyPairFactoryPtr & factory)
    {
        auto enc_result = kem->encapsulate(keys->getPublicKey());
        auto wrapped_key = enc_result.first;
        auto bob_secret = enc_result.second;
        auto alice_secret = kem->decapsulate(keys->getPrivateKey(), wrapped_key);
        ccstAssertEqual(bob_secret->getKeyData(), alice_secret->getKeyData());
        
        // test private key re-import
        auto exported_private_key = keys->getPrivateKey().exportKey();
        auto re_imported_private_key = factory->newPrivateKey(exported_private_key);
        auto alice_secret_2 = kem->decapsulate(*re_imported_private_key, wrapped_key);
        ccstAssertEqual(alice_secret->getKeyData(), alice_secret_2->getKeyData());
        // test public key re-import
        auto exported_public_key = keys->getPublicKey().exportKey();
        auto re_imported_public_key = factory->newPublicKey(exported_public_key);
        auto re_exported_public_key = re_imported_public_key->exportKey();
        ccstAssertEqual(re_exported_public_key, exported_public_key);
    }
    
    void testEncapDecap()
    {
        const std::vector<std::string> test_data = {
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
        };
        for (const auto & alg : test_data) {
            ccstMessage("%s", alg.c_str());
            auto kem = crypto::KeyEncapsulation::getInstance(alg);
            auto factory = crypto::KeyPairFactory::getInstance(alg);
            
            // Create keys with KEM interface
            auto keys = kem->generate();
            testsWithKeyPair(keys, kem, factory);
            // Create keys with Factory
            keys = factory->generateKeyPair();
            testsWithKeyPair(keys, kem, factory);
        }
    }

    void testMLKEM()
    {
        auto root = JSON_ParseFile(g_testFiles, "test-data/mlkem-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto algorithm = item.stringAtPath("algorithm");
            ccstMessage("%s", algorithm.c_str());
            auto factory = crypto::KeyPairFactory::getInstance(algorithm);
            auto kem = crypto::KeyEncapsulation::getInstance(algorithm);
            
            // Import test data and do the test
            auto private_key_data = item.dataFromBase64StringAtPath("privateKey");
            auto wrapped_key = item.dataFromBase64StringAtPath("wrappedKey");
            auto expected_secret = item.dataFromBase64StringAtPath("secret");
            
            auto private_key = factory->newPrivateKey(private_key_data);
            auto secret = kem->decapsulate(*private_key, wrapped_key)->getKeyData();
            ccstAssertEqual(expected_secret, secret);
        }
    }
    
    void generateMLKEM()
    {
        // NOTE: Uncomment test function in constructor, to generate new key sets
        
        // This test generates 1st part of the process. You have to then apply this
        // 
        auto root = JSON_ParseFile(g_testFiles, "test-data/mlkem-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto algorithm = item.stringAtPath("algorithm");
            auto factory = crypto::KeyPairFactory::getInstance(algorithm);
            auto kem = crypto::KeyEncapsulation::getInstance(algorithm);
            // Generate key-pair for selected algorithm
            auto keys = factory->generateKeyPair();
            ccstMessage("ALG = %s\n", algorithm.c_str());
            ccstMessage("  private = %s\n", keys->getPrivateKey().exportKeyToBase64().c_str());
            ccstMessage("  public  = %s\n", keys->getPublicKey().exportKeyToBase64().c_str());
        }
    }
};

CC7_CREATE_UNIT_TEST(KeyEncapsulationTests, "cc7")
    
} // cc7::tests
} // cc7
