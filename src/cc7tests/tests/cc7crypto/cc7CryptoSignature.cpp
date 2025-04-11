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

namespace cc7
{
namespace tests
{

class cc7CryptoSignature : public UnitTest
{
public:
    cc7CryptoSignature()
    {
        CC7_REGISTER_TEST_METHOD(testSignVerify);
        CC7_REGISTER_TEST_METHOD(testWrongKeys);
        CC7_REGISTER_TEST_METHOD(testMLDSA);
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
    
    void testMLDSA()
    {
        auto public_key = crypto::PublicKey::getInstance("ML-DSA-65");
        auto signer = crypto::Signature::getInstance("ML-DSA-65");
        auto key_data = std::string("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");
        public_key->importKeyFromBase64(key_data, crypto::KEY_FORMAT_DER);
        auto signature = ByteArray();
        signature.readFromBase64String("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");
        
        auto result = signer->verify(*public_key, signature, MakeRange("test_message"));
        ccstAssertTrue(result);
        
        auto exported = public_key->exportKeyToBase64(crypto::KEY_FORMAT_DER);
        ccstAssertEqual(key_data, exported);
    }
    

};

CC7_CREATE_UNIT_TEST(cc7CryptoSignature, "cc7")
    
} // cc7::tests
} // cc7
