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
#include <cc7/jwt/Jwt.h>
#include <cc7/crypto/Crypto.h>
#include <cc7/Base64.h>

using namespace cc7::json;
using namespace cc7::jwt;

namespace cc7
{
namespace tests
{
    extern TestDirectory g_testFiles;
    
    class JwtTests : public UnitTest
    {
    public:        
        JwtTests()
        {
            CC7_REGISTER_TEST_METHOD(testCompactTokens)
            CC7_REGISTER_TEST_METHOD(testSignVerify)
            CC7_REGISTER_TEST_METHOD(testMultiSignVerify)
        }
        
        struct CompactData
        {
            std::string token;
            bool success;
            jwt::JwtKeyPtr key;
        };
        
        static crypto::PublicKeyPtr publicKey(const std::string& alg, const std::string& data)
        {
            auto key = crypto::PublicKey::getInstance(alg);
            key->importKeyFromBase64(data);
            return key;
        }
        
        static crypto::PrivateKeyPtr privateKey(const std::string& alg, const std::string& data)
        {
            auto key = crypto::PrivateKey::getInstance(alg);
            key->importKeyFromBase64(data);
            return key;
        }
        
        void testCompactTokens()
        {
            std::vector<CompactData> test_data {
                { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
                    true,
                    JwtKey::symmetricKey("HS256", MakeRange("a-string-secret-at-least-256-bits-long"))
                },
                {
                    "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.owv7q9nVbW5tqUezF_G2nHTra-ANW3HqW9epyVwh08Y-Z-FKsnG8eBIpC4GTfTVU",
                    true,
                    JwtKey::symmetricKey("HS384", MakeRange("a-valid-string-secret-that-is-at-least-384-bits-long"))
                },
                {
                    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg",
                    true,
                    JwtKey::symmetricKey("HS512", MakeRange("a-valid-string-secret-that-is-at-least-512-bits-long-which-is-very-long"))
                },
                {
                    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
                    true,
                    JwtKey::publicKey(publicKey("P-256", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=="))
                },
                {
                    "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj",
                    true,
                    JwtKey::publicKey(publicKey("P-384", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii1D3jaW6pmGVJFhodzC31cy5sfOYotrzF"))
                    
                },
                {
                    "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk",
                    true,
                    JwtKey::publicKey(publicKey("P-521", "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZPDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib476MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwMAl8G7CqwoJOsW7Kddns="))
                }
            };
            
            for (const auto& td : test_data) {
                auto alg_name = td.key->getJwtAlgorithm().c_str();
                ccstMessage("%s %s", alg_name, td.success ? "success" : "failure");
                auto reader = JwtReader::fromCompact(td.token);
                try {
                    reader.verify({ td.key });
                    if (!td.success) {
                        ccstFailure("%s: verification should fail", alg_name);
                        break;
                    }
                    auto payload = JsonReader::fromJsonData(reader.getPayload());
                    ccstAssertEqual("1234567890", payload["sub"].asString());
                    ccstAssertEqual("John Doe", payload["name"].asString());
                    ccstAssertEqual(true, payload["admin"].asBoolean());
                    ccstAssertEqual(1516239022, payload["iat"].asInteger());
    
                } catch (JwtException & e) {
                    if (td.success) {
                        ccstFailure("%s: Validation failed", alg_name);
                        break;
                    }
                }
            }
        }
        
        struct SignVerifyData
        {
            JwtKeyPtr sign_key;
            JwtKeyPtr verify_key;
        };
        
        SignVerifyData testDataForDsa(const std::string& alg_name)
        {
            auto key_pair = crypto::KeyPair::generateKeyPair(alg_name);
            return {
                JwtKey::privateKey(key_pair->getPrivateKeyPtr()),
                JwtKey::publicKey(key_pair->getPublicKeyPtr())
            };
        }
        
        SignVerifyData testDataForMac(const std::string& alg, size_t size)
        {
            auto key = crypto::GetRandomData(size);
            return {
                JwtKey::symmetricKey(alg, key),
                JwtKey::symmetricKey(alg, crypto::SymmetricKey::getInstance(key))
            };
        }
        
        struct MultiSignVerifyData
        {
            std::string title;
            JwtKeyList sign_keys;
            JwtKeyList verify_keys;
        };
        
        MultiSignVerifyData testDataForAlgs(const std::vector<std::string>& algs)
        {
            std::string title;
            JwtKeyList sign, verify;
            for (auto alg : algs) {
                SignVerifyData td;
                if (alg == "HS256" || alg == "HS384" || alg == "HS512") {
                    td = testDataForMac(alg, 64);
                } else {
                    td = testDataForDsa(alg);
                }
                if (title.empty()) {
                    title = td.sign_key->getJwtAlgorithm();
                } else {
                    title += " + " + td.sign_key->getJwtAlgorithm();
                }
                sign.push_back(td.sign_key);
                verify.push_back(td.verify_key);
            }
            return { title, sign, verify };
        }
        
        void testSignVerify()
        {
            auto payload = Base64::urlDecode("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0");
            
            std::vector<SignVerifyData> tests;
            tests.push_back(testDataForDsa("P-256"));
            tests.push_back(testDataForDsa("P-384"));
            tests.push_back(testDataForDsa("P-521"));
            tests.push_back(testDataForDsa("ML-DSA-44"));
            tests.push_back(testDataForDsa("ML-DSA-65"));
            tests.push_back(testDataForDsa("ML-DSA-87"));
            tests.push_back(testDataForMac("HS256", 32));
            tests.push_back(testDataForMac("HS384", 48));
            tests.push_back(testDataForMac("HS512", 64));
            
            for (auto& td : tests) {
                ccstMessage("%s", td.sign_key->getJwtAlgorithm().c_str());
                auto compact = JwtWriter()
                                    .withPayload(payload)
                                    .sign({ td.sign_key })
                                    .toCompact();
                auto payload = JwtReader::fromCompact(compact)
                                    .verify({ td.verify_key })
                                    .getPayload();
                
                auto claims = JsonReader::fromJsonData(payload);
                ccstAssertEqual("1234567890", claims["sub"].asString());
                ccstAssertEqual("John Doe", claims["name"].asString());
                ccstAssertEqual(true, claims["admin"].asBoolean());
                ccstAssertEqual(1516239022, claims["iat"].asInteger());
            }
        }
        
        void testMultiSignVerify()
        {
            auto payload = Base64::urlDecode("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0");
            
            std::vector<MultiSignVerifyData> tests;
            tests.push_back(testDataForAlgs({ "P-256" }));
            tests.push_back(testDataForAlgs({ "HS256", "P-256" }));
            tests.push_back(testDataForAlgs({ "HS384", "P-384" }));
            tests.push_back(testDataForAlgs({ "P-256", "ML-DSA-44" }));
            tests.push_back(testDataForAlgs({ "ML-DSA-65", "P-384" }));
            tests.push_back(testDataForAlgs({ "HS512", "P-521", "ML-DSA-87" }));
            
            for (auto& td : tests) {
                ccstMessage("%s", td.title.c_str());
                auto json_data = JwtWriter()
                                    .withPayload(payload)
                                    .sign( td.sign_keys )
                                    .toJsonData();
                auto payload = JwtReader::fromJsonData(json_data)
                                    .verify( td.verify_keys )
                                    .getPayload();
                auto claims = JsonReader::fromJsonData(payload);
                ccstAssertEqual("1234567890", claims["sub"].asString());
                ccstAssertEqual("John Doe", claims["name"].asString());
                ccstAssertEqual(true, claims["admin"].asBoolean());
                ccstAssertEqual(1516239022, claims["iat"].asInteger());
            }
        }
    };
    
    CC7_CREATE_UNIT_TEST(JwtTests, "cc7 test")
    
} // cc7::tests
} // cc7
