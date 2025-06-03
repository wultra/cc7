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

namespace cc7
{
namespace tests
{

class KeyAgreementTests : public UnitTest
{
public:
    KeyAgreementTests()
    {
        CC7_REGISTER_TEST_METHOD(testECDH);
        CC7_REGISTER_TEST_METHOD(testECDHWrongKeys);
    }
    
    // UNIT TESTS
        
    void testECDH()
    {
        testECDHWithCurve("P-256", "NULL-KDF", 32);
        testECDHWithCurve("P-384", "NULL-KDF", 48);
        testECDHWithCurve("P-521", "NULL-KDF", 66);
    }
    
    void testECDHWithCurve(const char * curve_type, const char * kdf_type, size_t key_size)
    {
        auto alice_key_pair = crypto::KeyPair::generateKeyPair(curve_type);
        auto bob_key_pair = crypto::KeyPair::generateKeyPair(curve_type);
        auto key_agreement = crypto::KeyAgreement::getInstance("ECDH", kdf_type);
        
        auto alices_ss = key_agreement->phase(alice_key_pair->getPrivateKey(), bob_key_pair->getPublicKey());
        auto bobs_ss = key_agreement->phase(bob_key_pair->getPrivateKey(), alice_key_pair->getPublicKey());
        auto alice_ss_data = alices_ss->getKeyData();
        auto bob_ss_data = bobs_ss->getKeyData();
        
        auto size_ok = key_size == alices_ss->getKeyData().size();
        auto ss_ok   = alice_ss_data == bob_ss_data;
        if (!size_ok || !ss_ok) {
            ccstMessage("ECDH with %s: failed", kdf_type);
            if (!ss_ok) {
                ccstMessage("alice ss : %s", alice_ss_data.hexString().c_str());
                ccstMessage("  bob ss : %s", bob_ss_data.hexString().c_str());
            }
            if (!size_ok) {
                ccstMessage("wrong expected size : %d vs %d", key_size, alice_ss_data.size());
            }
            ccstFailure("ECDH or KDF is broken");
        }
    }
    
    void testECDHWrongKeys()
    {
        const std::vector<std::string> key_types = {
            "P-256", "P-384", "P-521", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
        };
        auto count = key_types.size();
        
        auto key_agreement = crypto::KeyAgreement::getInstance("ECDH", crypto::KeyDerivation::noDerivation());
        for (size_t i = 0; i < count; i++) {
            for (size_t j = i + 1; j < count; j++) {
                auto kp1 = crypto::KeyPair::generateKeyPair(key_types[i]);
                auto kp2 = crypto::KeyPair::generateKeyPair(key_types[j]);
                ccstMustThrow(std::exception, key_agreement->phase(kp1->getPrivateKey(), kp2->getPublicKey()));
            }
        }
    }
};

CC7_CREATE_UNIT_TEST(KeyAgreementTests, "cc7")
    
} // cc7::tests
} // cc7
