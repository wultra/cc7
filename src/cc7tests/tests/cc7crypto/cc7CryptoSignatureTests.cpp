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

class cc7CryptoSignatureTests : public UnitTest
{
public:
    cc7CryptoSignatureTests()
    {
        CC7_REGISTER_TEST_METHOD(testSignVerify);
        CC7_REGISTER_TEST_METHOD(testWrongKeys);
        CC7_REGISTER_TEST_METHOD(testSignatureVerification);
    }
    
    // UNIT TESTS
        
    void testSignVerify()
    {
        testWithSigner(crypto::Signature::getInstance("ECDSA-SHA-256"), crypto::KeyPair::generateKeyPair("P-256"));
        testWithSigner(crypto::Signature::getInstance("ECDSA-SHA-384"), crypto::KeyPair::generateKeyPair("P-384"));
        testWithSigner(crypto::Signature::getInstance("ECDSA-SHA-512"), crypto::KeyPair::generateKeyPair("P-521"));
        testWithSigner(crypto::Signature::getInstance("ECDSA-SHA3-256"), crypto::KeyPair::generateKeyPair("P-256"));
        testWithSigner(crypto::Signature::getInstance("ECDSA-SHA3-384"), crypto::KeyPair::generateKeyPair("P-384"));
        testWithSigner(crypto::Signature::getInstance("ECDSA-SHA3-512"), crypto::KeyPair::generateKeyPair("P-521"));
        
        testWithSigner(crypto::Signature::getInstance("ML-DSA-44"), crypto::KeyPair::generateKeyPair("ML-DSA-44"));
        testWithSigner(crypto::Signature::getInstance("ML-DSA-65"), crypto::KeyPair::generateKeyPair("ML-DSA-65"));
        testWithSigner(crypto::Signature::getInstance("ML-DSA-87"), crypto::KeyPair::generateKeyPair("ML-DSA-87"));
    }
    
    void testWithSigner(const std::shared_ptr<crypto::Signature> & signer, const std::shared_ptr<crypto::KeyPair> & keyPair)
    {
        auto data_to_sign = crypto::GetRandomData(64);
        ccstAssertEqual(64, data_to_sign.size());
        
        auto signature = signer->sign(keyPair->getPrivateKey(), data_to_sign);
        ccstAssertFalse(signature.empty());

        auto result = signer->verify(keyPair->getPublicKey(), signature, data_to_sign);
        if (!result) {
            ccstMessage("%s with %s: failed", signer->getAlgorithmName().c_str(), keyPair->getPublicKey().getKeyType().c_str());
            ccstFailure("ECDSA verify is broken");
        }
    }
    
    void testWrongKeys()
    {
        // TODO: ...
    }
    
    void testSignatureVerification()
    {
        auto root = JSON_ParseFile(g_testFiles, "test-data/signature-test-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto algorithm = item.stringAtPath("alg");
            auto publicKeyFmtStr = item.containsValueAtPath("pubKeyFmt") ? item.stringAtPath("pubKeyFmt") : "default";
            auto publicKeyFmt = crypto::KeyFormat_FromString(publicKeyFmtStr);
            auto publicKeyType = item.containsValueAtPath("pubKeyType") ? item.stringAtPath("pubKeyType") : algorithm;
            if (algorithm == publicKeyType) {
                ccstMessage("%s, fmt: %s", algorithm.c_str(), publicKeyFmtStr.c_str());
            } else {
                ccstMessage("%s with %s, fmt: %s", algorithm.c_str(), publicKeyType.c_str(), publicKeyFmtStr.c_str());
            }
            auto publicKey = crypto::PublicKey::getInstance(publicKeyType);
            publicKey->importKeyFromBase64(item.stringAtPath("pubKey"), publicKeyFmt);
            for (const auto & td : item.arrayAtPath("tests")) {
                auto message = td.dataFromBase64StringAtPath("message");
                auto signature = td.dataFromBase64StringAtPath("signature");
                auto expected_result = td.booleanAtPath("result");
                auto verifier = crypto::Signature::getInstance(algorithm);
                auto result = verifier->verify(*publicKey, signature, message);
                ccstAssertEqual(expected_result, result);
            }
        }
    }
    

};

CC7_CREATE_UNIT_TEST(cc7CryptoSignatureTests, "cc7")
    
} // cc7::tests
} // cc7
