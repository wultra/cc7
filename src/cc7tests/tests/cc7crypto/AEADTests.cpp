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
#include <cc7/Base64.h>
#include <cc7tests/JSONReader.h>
#include <cc7tests/TestDirectory.h>

namespace cc7
{
namespace tests
{
extern TestDirectory g_testFiles;

class AEADTests : public UnitTest
{
public:
    AEADTests()
    {
        CC7_REGISTER_TEST_METHOD(testEncrypDecrypt);
        CC7_REGISTER_TEST_METHOD(testVectors);
    }
    
    // UNIT TESTS
    
    struct TestData {
        std::string algorithm;
        std::string key_type;
        size_t key_size;
        size_t iv_size;
        bool support_context;
    };

    static ByteArray getRandomData()
    {
        size_t data_size = arc4random_uniform(513);
        return crypto::GetRandomData(data_size);
    }
    
    void testEncrypDecrypt()
    {
        static const TestData s_test_data[] = {
            { "AES-128-GCM#I12T16D", "AES-128", 16, 12, false },
            { "AES-192-GCM#I12T16D", "AES-192", 24, 12, false },
            { "AES-256-GCM#I12T16D", "AES-256", 32, 12, false },
            { "AES-128-GCM#I12T16D", "AES-128", 16, 0,  false },
            { "AES-192-GCM#I12T16D", "AES-192", 24, 0,  false },
            { "AES-256-GCM#I12T16D", "AES-256", 32, 0,  false },
        };
        for (const auto & td : s_test_data) {
            auto encryptor = crypto::AEAD::getInstance(td.algorithm);
            ccstMessage("%s + %s", td.algorithm.c_str(), td.key_type.c_str());
            for (int i = 0; i < 100; i++) {
                auto enc_params = crypto::ParameterList();
                auto dec_params = crypto::ParameterList();
                auto enc_key = crypto::GetRandomData(td.key_size);
                auto dec_key = crypto::SymmetricKey::getInstance(td.key_type, enc_key);
                if (td.support_context) {
                    auto key_ctx = getRandomData();
                    enc_params[crypto::PARAM_KEY_CONTEXT] = crypto::Parameter::ref(key_ctx);
                    dec_key->setKeyContext(key_ctx);
                }
                auto iv = td.iv_size > 0 ? crypto::GetRandomData(td.iv_size) : ByteArray();
                auto aad       = getRandomData();
                auto plaintext = getRandomData();
                auto encrypted = encryptor->seal(enc_key, iv, aad, plaintext, enc_params);
                auto decrypted = encryptor->open(*dec_key, aad, encrypted, dec_params);
                if (plaintext != decrypted) {
                    ccstMessage("Plain     : %s", plaintext.hexString().c_str());
                    ccstMessage("Decrypted : %s", decrypted.hexString().c_str());
                    ccstFailure("%s is broken", td.algorithm.c_str());
                    return;
                }
            }
        }
    }
    
    void testVectors() {
        auto root = JSON_ParseFile(g_testFiles, "test-data/aead-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & entry : data) {
            auto alg = entry.stringAtPath("alg");
            ccstMessage("%s", alg.c_str());
            auto encryptor = crypto::AEAD::getInstance(alg);
            auto vectors = entry.arrayAtPath("vectors");
            for (const auto & td : vectors) {
                auto key = td.dataFromHexStringAtPath("key");
                auto iv  = td.dataFromHexStringAtPath("iv");
                auto aad = td.dataFromHexStringAtPath("aad");
                auto expected_plaintext = td.dataFromHexStringAtPath("pt");
                auto expected_ciphertext = td.dataFromHexStringAtPath("ct");
                crypto::ParameterList encrypt_params;
                crypto::ParameterList decrypt_params;
                if (td.containsValueAtPath("kct")) {
                    // key context
                    auto kct = td.dataFromHexStringAtPath("kct");
                    encrypt_params[crypto::PARAM_KEY_CONTEXT] = crypto::Parameter::copy(kct);
                    decrypt_params[crypto::PARAM_KEY_CONTEXT] = crypto::Parameter::copy(kct);
                }
                auto ciphertext = encryptor->seal(key, iv, aad, expected_plaintext, encrypt_params);
                auto extract_iv = encryptor->extractNonce(ciphertext);
                auto plaintext  = encryptor->open(key, aad, ciphertext, decrypt_params);
                if (expected_ciphertext != ciphertext) {
                    ccstFailure("%s encrypt is broken", alg.c_str());
                    ccstMessage("  expected : %s", expected_ciphertext.hexString().c_str());
                    ccstMessage("   actual  : %s", ciphertext.hexString().c_str());
                    return;
                }
                if (expected_plaintext != plaintext) {
                    ccstFailure("%s decrypt is broken", alg.c_str());
                    ccstMessage("  expected : %s", expected_plaintext.hexString().c_str());
                    ccstMessage("   actual  : %s", plaintext.hexString().c_str());
                    return;
                }
                if (iv != extract_iv) {
                    ccstFailure("%s extract iv is broken", alg.c_str());
                    ccstMessage("  expected : %s", iv.hexString().c_str());
                    ccstMessage("   actual  : %s", extract_iv.hexString().c_str());
                    return;
                }

            }
        }
    }
};

CC7_CREATE_UNIT_TEST(AEADTests, "cc7")
    
} // cc7::tests
} // cc7
