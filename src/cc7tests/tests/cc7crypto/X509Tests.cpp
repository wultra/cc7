/*
 * Copyright 2026 Wultra s.r.o.
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

namespace cc7::tests {

class X509Tests : public UnitTest
{
public:
    X509Tests()
    {
        CC7_REGISTER_TEST_METHOD(testCreateCSR);
        CC7_REGISTER_TEST_METHOD(testWrongKeyTypesForCSR);
    }
    
    const bool dumpCSR = false;
    
    void testCreateCSR()
    {
        const auto algs = std::vector<std::string> {
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "P-256", "P-384", "P-521",
        };
        auto dn = std::map<std::string, std::string> {
            { "C", "CZ" },
            { "O", "Example" },
            { "CN", "example.com" }
        };
        auto san = std::vector<std::string> {
            "DNS:example.com",
            "DNS:www.example.com"
        };
        for (auto alg : algs) {
            ccstMessage("%s", alg.c_str());
            auto keyPair = cc7::crypto::KeyPair::generateKeyPair(alg);
            // re-export key
            auto privateKey = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(keyPair->getPrivateKey().duplicate());
            ccstAssertNotNull(privateKey);
            
            auto csr = cc7::crypto::X509::createCSR(*privateKey, dn, {});
            ccstAssertFalse(csr.empty());
            if (dumpCSR) ccstMessage("CSR (no ext):\n%s", csr.c_str());
            csr = cc7::crypto::X509::createCSR(*privateKey, dn, san);
            ccstAssertFalse(csr.empty());
            if (dumpCSR) ccstMessage("CSR (with ext):\n%s", csr.c_str());
        }
    }
    
    void testWrongKeyTypesForCSR()
    {
        const auto algs = std::vector<std::string> {
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
            "DHKEM-P256-HKDF-SHA256", "DHKEM-P384-HKDF-SHA384", "DHKEM-P521-HKDF-SHA512"
        };
        auto dn = std::map<std::string, std::string> {
            { "C", "CZ" },
            { "O", "Example" },
            { "CN", "example.com" }
        };
        for (auto alg : algs) {
            auto keyPair = cc7::crypto::KeyPair::generateKeyPair(alg);
            ccstMustThrow(std::exception, cc7::crypto::X509::createCSR(keyPair->getPrivateKey(), dn, {}));
        }
    }
};

CC7_CREATE_UNIT_TEST(X509Tests, "cc7")
    
} // cc7

