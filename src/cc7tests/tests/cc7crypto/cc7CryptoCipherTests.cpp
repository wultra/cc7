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

class cc7CryptoCipherTests : public UnitTest
{
public:
    cc7CryptoCipherTests()
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
        size_t block_size;
        bool need_padding;
    };

    static ByteArray getRandomData(const TestData & td, bool aligned)
    {
        size_t data_size;
        if (aligned) {
            data_size = arc4random_uniform(7) * td.block_size;
        } else {
            data_size = arc4random_uniform(73);
        }
        return crypto::GetRandomData(data_size);
    }
    
    void testEncrypDecrypt()
    {
        static const TestData s_test_data[] = {
            { "AES-128-ECB", "AES-128",     16, 0,  16, true },
            { "AES-192-ECB", "AES-192",     24, 0,  16, true },
            { "AES-256-ECB", "AES-256",     32, 0,  16, true },
            { "AES-128-CBC", "AES-128",     16, 16, 16, true },
            { "AES-192-CBC", "AES-192",     24, 16, 16, true },
            { "AES-256-CBC", "AES-256",     32, 16, 16, true },
            { "AES-128-CTR", "AES-128",     16, 16, 16, false },
            { "AES-192-CTR", "AES-192",     24, 16, 16, false },
            { "AES-256-CTR", "AES-256",     32, 16, 16, false },
            
            { "AES-128-ECB", "GENERIC-128", 16, 0,  16, true },
            { "AES-192-ECB", "GENERIC-192", 24, 0,  16, true },
            { "AES-256-ECB", "GENERIC-256", 32, 0,  16, true },
            { "AES-128-CBC", "GENERIC-128", 16, 16, 16, true },
            { "AES-192-CBC", "GENERIC-192", 24, 16, 16, true },
            { "AES-256-CBC", "GENERIC-256", 32, 16, 16, true },
            { "AES-128-CTR", "GENERIC-128", 16, 16, 16, false },
            { "AES-192-CTR", "GENERIC-192", 24, 16, 16, false },
            { "AES-256-CTR", "GENERIC-256", 32, 16, 16, false },

        };
        for (const auto & td : s_test_data) {
            auto encryptor = crypto::Cipher::getInstance(td.algorithm);
            for (int i = 0; i < 100; i++) {
                auto enc_key = crypto::GetRandomData(td.key_size);
                auto dec_key = crypto::SymmetricKey::getInstance(td.key_type, enc_key);
                auto iv = td.iv_size > 0 ? crypto::GetRandomData(td.iv_size) : ByteArray();
                auto plaintext = getRandomData(td, false);
                auto encrypted = encryptor->encrypt(enc_key, iv, plaintext);
                auto decrypted = encryptor->decrypt(*dec_key, iv, encrypted);
                if (plaintext != decrypted) {
                    ccstMessage("Plain     : %s", plaintext.hexString().c_str());
                    ccstMessage("Decrypted : %s", decrypted.hexString().c_str());
                    ccstFailure("%s is broken", td.algorithm.c_str());
                    return;
                }
            }
            if (td.need_padding) {
                encryptor = crypto::Cipher::getInstance(td.algorithm);
                encryptor->setParameter(crypto::CIPHER_PARAM_USE_PADDING, crypto::Parameter::from(false));
                auto dec_key = crypto::GetRandomData(td.key_size);
                auto enc_key = crypto::SymmetricKey::getInstance(td.key_type, dec_key);
                auto key = crypto::GetRandomData(td.key_size);
                auto iv = td.iv_size > 0 ? crypto::GetRandomData(td.iv_size) : ByteArray();
                auto plaintext = getRandomData(td, true);
                auto encrypted = encryptor->encrypt(*enc_key, iv, plaintext);
                auto decrypted = encryptor->decrypt(dec_key, iv, encrypted);
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
        auto root = JSON_ParseFile(g_testFiles, "test-data/cipher-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & entry : data) {
            auto alg = entry.stringAtPath("alg");
            auto encryptor = crypto::Cipher::getInstance(alg);
            if (entry.booleanAtPath("pad")) {
                encryptor->setParameter(crypto::CIPHER_PARAM_USE_PADDING, crypto::Parameter::from(false));
            }
            auto vectors = entry.arrayAtPath("vectors");
            for (const auto & td : vectors) {
                auto key = td.dataFromHexStringAtPath("key");
                auto iv = td.dataFromHexStringAtPath("iv");
                auto expected_plaintext = td.dataFromHexStringAtPath("pt");
                auto expected_ciphertext = td.dataFromHexStringAtPath("ct");
                auto ciphertext = encryptor->encrypt(key, iv, expected_plaintext);
                auto plaintext = encryptor->decrypt(key, iv, expected_ciphertext);
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
                
            }
        }
    }
};

CC7_CREATE_UNIT_TEST(cc7CryptoCipherTests, "cc7")
    
} // cc7::tests
} // cc7
