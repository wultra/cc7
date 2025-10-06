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
#include "../src/cc7/jwt/JwsSpec.h"

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
            CC7_REGISTER_TEST_METHOD(testCompositeSignatures)
            CC7_REGISTER_TEST_METHOD(testSignVerify)
            CC7_REGISTER_TEST_METHOD(testMultiSignVerify)
        }
        
        static const int TEST_OK = 0;
        static const int TEST_COMMON_DATA = 1;
        static const int TEST_FAIL = 2;
        
        struct CompactData
        {
            std::string token;
            jwt::JwsKeyPtr key;
            int testMode;
        };
        
        struct CompositeData
        {
            std::string signature;
            JwsKeyList keys;
            int testMode;
        };
        
        static crypto::PublicKeyPtr publicKey(const std::string& alg, const std::string& data, cc7::crypto::KeyFormat format = cc7::crypto::KEY_FORMAT_DEFAULT)
        {
            auto key = crypto::PublicKey::getInstance(alg);
            key->importKeyFromBase64(data, format);
            return key;
        }
        
        static crypto::PrivateKeyPtr privateKey(const std::string& alg, const std::string& data, cc7::crypto::KeyFormat format = cc7::crypto::KEY_FORMAT_DEFAULT)
        {
            auto key = crypto::PrivateKey::getInstance(alg);
            key->importKeyFromBase64(data, format);
            return key;
        }
        
        void testCompactTokens()
        {
            std::vector<CompactData> test_data {
                // powerauth-crypto test vectors
                {
                    "eyJhbGciOiJIUzI1NiJ9.eyJhcHBsaWNhdGlvbktleSI6IjdoNHNFVGtUK0hwS05DZmk2eWVyR2c9PSIsImNoYWxsZW5nZSI6IlJGZEJuTjg3QkMvK0pWYWZUZTU5T09NSSIsInNoYXJlZFNlY3JldFJlcXVlc3QiOnsiYWxnb3JpdGhtIjoiRUNfUDM4NCIsImVjZGhlIjoiQkpzUDIwT2FYZHFXVWgwd1V6QmRXVlViZ0lQeFhzWjlSa2hZS0xPdmJhcS96QlFFMnFXWktIY3dZQk41N0F5U2hLUndlQlVlTERUZ3g2OGZHNCtsNlNKb2ozV0gxSmpXb2FVSmVvWW9PNFNwQ1J5QVFjYVdXVlB5T2FMdjlqdUpMdz09In0sImV4cCI6MTc0OTgxMDU3NCwiaWF0IjoxNzQ5ODEwMjc0fQ.uSGPoOVyA3AsVxk4RhzMwgPuNe5SjdwbngqHbVxDBjE",
                    JwsKey::symmetricKey("HS256", Base64::decode("USlRczeq9SsWGnU+NUmmFMlFwJzsC43CFQvYZeBqnEg=")),
                    TEST_OK
                },
                {
                  "eyJhbGciOiJIUzI1NiJ9.eyJhcHBsaWNhdGlvbktleSI6IjdoNHNFVGtUK0hwS05DZmk2eWVyR2c9PSIsImNoYWxsZW5nZSI6IlhuMVlhUXJJK04waTRZQWRvRWZwUDN4LyIsInNoYXJlZFNlY3JldFJlcXVlc3QiOnsiYWxnb3JpdGhtIjoiRUNfUDM4NF9NTF9MMyIsImVjZGhlIjoiQkkzdCt0T3VOUE45UzJMZ29ISWVjbWJoSTB0RjQ5RmxDcDBKYithYWpDYkVTTmJlaVJnVG9GdG53cG5Cd29mWlNEbjJnUlo3NFhJUGJvR0ZhUTlSVXhjYld2L1R5L1lodlcwakhJS0o4eFhHMUVqZ0I0cEkyZXdkRjZhR0xCd2NMdz09IiwibWxrZW0iOiJNSUlFc2pBTEJnbGdoa2dCWlFNRUJBSURnZ1NoQUc5NkFuY3lqZ1dCblI3bGN1R0x4bWx3a21jSEpITHl2WlBwdVJ1N3JUb0tubHZabG5QVW9HcWpJSThBdC8rN2h2ak1ycWkxVTI0YUpVckxnbGdoaUY1SFRSZ0VaV0dXUHI1d0FTWXdzZGlqa0hzeVF2cldMUzBYc3pxSVFFQnJsdFBIcERFRHNNK1hsWWoxazgxb3d3bFVQSGRUb3dEV2FZblFTSGZhbFJ1alBRRldCcHIxQWpnc2IyYTFPRzVWQU5lRnQzRlhhOGFqZnZPR1hOWFFlb01oSTJmcUIrMDFiR1pzYWhQWXBVb0RFWlBIeDI1QWZVamdFRWZLVzJUQ1hxZUp5NlRVbjhSeG12djZhT0lXQkd5VXE2K0duTlNWU1MrRm1XT2lMdXE0eVZVanI0SFRHVmhKcU84S2RFRjVlSzVteU9CaXlqT2JuNE1qUXVYaWNoNG5HWk5HR3A3bnNzQ0dRVkFSZ2FMN0dvTTJGWThqRlpDd1E1WFFVQVZ3Z2dXcHVOMUZWcVhJR3NOekN6Y0pyK0lWcWtIcGtSVERuSWtYSTVtbk9RdFFZYzVJZ0ZmM05aS1RodFFuckJ6Z1ZnOVNOUkIwYXdnVG9SWjdnN21vbWZwb0puSUR6N3BFTUNxalR1cmxGRU5JUlZueEptN21SQ0tKZzVNWm43VExaWkVrdExGMlkxc1dGbGtYbkhmOHBJczh1MFBIdndzZ1FXcWdlbVpWYlRsRWlOanp1eWZycC93M2loMlFzd3NnT2RXRWp5bXhuRGJibDJER2w2eVhDU0QxS1ljd0t6RE1RVlhZWmpsSG9XMmtjWTZWeFU4UUErSlhjZjBYdGs0akNBR3pGZlFFTERIYWF3YlpOV0VUSjVvY2lYUTRTSGphRXpTcFdyaFNESGEwZHl3NGdqVmp6S2JjUjJsaU1VVkRFREdWTnNvbXpaZkdoaVhHZjBxbGtLMURVajBVc25saVd3TGNGbkMwZkRFb204REhrTXlMaCtMc2luYU1xK2FBaXlpalpETWNrRjhnZXhhMHdmMkJTYWlobGZlSmxJV3JIZFBLRzQ5TGUxam1RMk03WmxWNkZnSzRxaldxdTdUVVJuSDBadVZpRS9NMUwwUkJ0blZubC9kS3NwOWd6NHJKQkE2eGZmN1JIcm5vbExRenpzOXlDc21xSFdWeEJ6d0FWbTVZSTdRWkFCN0hjV0x6Y2ZMWG9uYTRXVnFaaEtqUk1UZFFtMmdKWXBqQm5wVGNJWk5sVGRWclNCVmFNMm42dFMxSlRqY1ZLRVd3RTNYMUhYTjZLZVdGaFBTRU1CaGxKdkRESDFhVHhPb25kMkd4S3hJd0x6NnhRVFczaHBGb01KSUFxOXZFaHIreklhZ1NPc1JJeHh1bERXQ1dtb256c1JGTWtaVnBGdGxiQkIra3BqbktCZ0VGcFg5RWtsNWhOMFY0a3JZMXA2ejJWQmRBV3ZJQVlVaGxlZmlYYUo2Z1k5V2thNXRzR3ZXaFpuUVFZcEdxcmZpQ0lHaWpqWEV4ZWVSTGtrdlp0T1hxQ2g4YmY1UVNFVkFCQmZaOFVHb0JqTUdsc0tCN0ZJa1VVWDdnZ3VRN01DSzZtejRUZkkvVkYrRWNDZzdRVWhFa004TEZmWUZzeTV4anhEZzNwSGZJV3dpcEpUeGtJdnF6VmdlQ2pRS2hob21zRjdEa3hxOVVFaTREZGNBQkxxRDdWQVJzdmcyREtXaE1kMU9KaXU1Q2Vic1dYN0Q1Vy9Ec1dQd01LT014aktNeXFBTEFWTkpTSXVrc3BNa0FLSERGRG85VlB2eDJFNStTbktxb01WWG1Pa2NoY25acnZrcVNySWpwTVpMS1JqY1ZtMzhjdW5LMndyTWhLamV6R01NR0ZKY2haeUpsV0l1NXhub0RYN3AxZ0hRclhKVFJvdy9YQkc3M2Q3ZDN6SG5hUzJiQXhXS2FFaTREaHJ0S2ZGMmprWUY1ZEkyamFMTmhjRXkyQUlIQ3dxQTZSWGlNT3dRMlMxQVVOaVJzRndveU4xZjVDZW9YTXg4QWRRL2J4MUJUVTF4MXNQdWtlN2JIMjFLa1JPV0E1dEg2TDQ0WDZqK3EifSwiZXhwIjoxNzQ5ODEwMzA1LCJpYXQiOjE3NDk4MTAwMDV9.XFw__3O5Uf9w7cZIDqgRoAMTrVxplvbbebjUgsimEg0",
                    JwsKey::symmetricKey("HS256", Base64::decode("USlRczeq9SsWGnU+NUmmFMlFwJzsC43CFQvYZeBqnEg=")),
                    TEST_OK
                },
                // test vectors generated at jwt.io
                {
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
                    JwsKey::symmetricKey("HS256", MakeRange("a-string-secret-at-least-256-bits-long")),
                    TEST_COMMON_DATA
                },
                {
                    "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.owv7q9nVbW5tqUezF_G2nHTra-ANW3HqW9epyVwh08Y-Z-FKsnG8eBIpC4GTfTVU",
                    JwsKey::symmetricKey("HS384", MakeRange("a-valid-string-secret-that-is-at-least-384-bits-long")),
                    TEST_COMMON_DATA
                },
                {
                    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg",
                    JwsKey::symmetricKey("HS512", MakeRange("a-valid-string-secret-that-is-at-least-512-bits-long-which-is-very-long")),
                    TEST_COMMON_DATA
                },
                {
                    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
                    JwsKey::publicKey(publicKey("P-256", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==")),
                    TEST_COMMON_DATA
                },
                {
                    "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj",
                    JwsKey::publicKey(publicKey("P-384", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii1D3jaW6pmGVJFhodzC31cy5sfOYotrzF")),
                    TEST_COMMON_DATA
                },
                {
                    "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk",
                    JwsKey::publicKey(publicKey("P-521", "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZPDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib476MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwMAl8G7CqwoJOsW7Kddns=")),
                    TEST_COMMON_DATA
                }
            };
            
            for (const auto& td : test_data) {
                auto alg_name = td.key->getJwtAlgorithm().c_str();
                ccstMessage("%s %d", alg_name, td.testMode);
                auto reader = JwtReader::fromCompact(td.token);
                try {
                    reader.verify({ td.key });
                    if (td.testMode == TEST_FAIL) {
                        ccstFailure("%s: verification should fail", alg_name);
                        break;
                    }
                    if (td.testMode == TEST_COMMON_DATA) {
                        auto payload = JsonReader::fromJsonData(reader.getPayload());
                        ccstAssertEqual("1234567890", payload["sub"].asString());
                        ccstAssertEqual("John Doe", payload["name"].asString());
                        ccstAssertEqual(true, payload["admin"].asBoolean());
                        ccstAssertEqual(1516239022, payload["iat"].asInteger());
                    }
                } catch (JwtException & e) {
                    if (td.testMode != TEST_FAIL) {
                        ccstFailure("%s: Validation failed", alg_name);
                        break;
                    }
                }
                if (td.key->getType() == jwt::JwsKey::Type::SYMMETRIC && td.testMode != TEST_FAIL) {
                    auto writer = JwtWriter();
                    try {
                        auto header = reader.getHeaders().front();
                        auto compact = writer.withPayload(reader.getPayload(), header.getType())
                            .sign({ td.key })
                            .toCompact();
                        ccstAssertEqual(td.token, compact);
                    } catch (...) {
                        ccstFailure("%s: Writer validation failed", alg_name);
                        break;
                    }
                }
            }
        }
        
        void testCompositeSignatures()
        {
            const std::vector<CompositeData> composite_vectors {
                {
                    "{\"payload\":\"eyJpYXRfbXMiOjE3NDk4MTAyNzQ5NTIsImV4cF9tcyI6MTc0OTgxMDU3NDk1Miwic3ViIjoiOWJjOTAzNGUtYTM5Yy00ZGNkLWJhMTktYjc3NWVmMzc2MzQ3IiwiYXBwbGljYXRpb25LZXkiOiI3aDRzRVRrVCtIcEtOQ2ZpNnllckdnPT0iLCJjaGFsbGVuZ2UiOiJSRmRCbk44N0JDLytKVmFmVGU1OU9PTUkiLCJleHAiOjE3NDk4MTA1NzQsInNoYXJlZFNlY3JldFJlc3BvbnNlIjp7ImVjZGhlIjoiQkN1eWd4Wjc4VnVTdXNYZUtJNk5lYmwyRm40OVYvTWZsaFl2V3Z2alhyVWlVaUNWVnJ1UUNoUGZzMGUyNTQ5ZnF4bm4vMHBTSXJsb0lGSHVRMXUyWStKUWFxeGFjVzBYMGtTUTdIMjNEaUxsanhWV0VrS0h3VnV5QVY3R3Q4UWdIQT09IiwibWxrZW0iOm51bGx9LCJpYXQiOjE3NDk4MTAyNzR9\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzM4NCJ9\",\"signature\":\"9j2A7vZeCMl38JhKpqt1kqepPu09mw9UR05x1BDeAIFiA5afpVYfjhQ_JwmnLeNAUBto6qoQwM9d00pF4DVJOpfkMFmHwCXB0KVmxNkYE0bFq9zIjsNdKnwJ6254lTPJ\"}]}",
                    {
                        JwsKey::publicKey(publicKey("P-384", "BG/pz6Gomet1gaEhki+xcaWM4gPs119wG7MpjsmlryuuUqQ5l/qia6vrjpDUDGCpp1VmiGambEl42k1bDeNBPhUQW/lZxoVZQeQrBwJjF++AyP4P5vXxQ3hOUYRrpKCjmg==", crypto::KEY_FORMAT_RAW))
                    },
                    TEST_OK
                },
                {
                    "{\"payload\":\"eyJpYXRfbXMiOjE3NDk4MTAwMDYzNDcsImV4cF9tcyI6MTc0OTgxMDMwNjM0Nywic3ViIjoiZjY3OTA1YzUtNDg5OC00YjVhLTg5YWEtZjA5M2VmNmEyNjc3IiwiYXBwbGljYXRpb25LZXkiOiI3aDRzRVRrVCtIcEtOQ2ZpNnllckdnPT0iLCJjaGFsbGVuZ2UiOiJYbjFZYVFySStOMGk0WUFkb0VmcFAzeC8iLCJleHAiOjE3NDk4MTAzMDYsInNoYXJlZFNlY3JldFJlc3BvbnNlIjp7ImVjZGhlIjoiQkI0RURERHJQc3ZHenMreDVaUDBLeStLaThqQzJnbUJIUzNEVldHbytGejczUGk4TEtWNGhxVy9idmtvaUlWeDhyRi9KNUxtOHR2QmlJS0RNa2ZZNk5KVjlLVFJDMUMrMm9MamFOMkxwdkhCOGZ1QjlWSEtLY2kwZWRxcjdXNVRHdz09IiwibWxrZW0iOiJQQ0VNUCszSnRNTGVBYkttZ1VUZ0doalB1L3UwNExEOFhKOHJpWEZnWWo2N2h5cm1HNjVGQ0dWSENmdC9OZ2orbUpLUlJMYzNOMVhQK0N2d3lVM1BvaXE4YW4reUJOVWUvYWhha2FuMi95MjRGMU5lcHJ0cTJOQUp6UWVHY05kYUlWU3VSYzR6SUVhbGFIMzFOMzF0RlBXMCtTYnEvNHhuTmZKNU51NTBEUGUrSFVSY2ErU08vbUd3RVRPNmllM1VzRU1USWVFU0psZzI5WXg3MitVYnRLQzlrZTRQOFoySkVFeHI4Q2t5Rm9ibHVBdkkyellsbnFRZ2wvK0pOc1h2dDdKVW83cWZ2Z2NtQ1lZZUNsdVRqNGJMN0g2T0o5UWE1MlUra3NKTVB1bjlRK0dmVjRTTXByUU13aUNkakNMMWJlSUNjVmVaTEhpQk5PaDdseDkycm52dlJIMlM5NDVlN3IvREhRSXdsSWprcWFMaVp1c3hjM2t0dVhwRnB1d0ZEMGlHVWVNeEFlNG9hdVhJRmlET1NKaS9nK2JmbnhXSnZDYVVmRm8wUm5WMW1vQ2tvTWN2OXUvTDVPbGJLUGNFQjhEU25Rajc4UjV4MVd1QUZYSnkzVnlHNHl6Rzc0TVpia1p4aTV4WEhEZE1QYzBEM3RVeklYZHZ4RHRhdnVyK2FHMEJreUNJaDhSU1ZDM3pIWjhtem5EY0l5amw1eVVGb2ErNVlJcmtwMVVtWEZBbUFpeG9tQjNadmFmbU53MkM5K3VNdmt4Q0h2Z3VRelk3OEJ3MUR5TFJScWI2N1Bhd0N2UkFKN1NtL1A3V2tEaUU3N2JTYUphZ3BxS05zWmNJL2FoMjlvaytGQUZNVWdkUjA4M3lTbFZRbDF3T0lEU3ZoNkVBYmZhWWR6bjVvWjZWZDdiZnREbXhhd3lhNGZsNEx3a0VzVlJrTm04U010MkFGditRUlgwSmdqZFpBZER1T1U3U2Q1QTE1T1RKcG16ZmZTNDdYOGp1emlqc0o4eFFKV1cycmt1UDBHWjVrWmZyU0NVRVJZNGZoWkVnaHFZVG0xNjNoZ1BESDhpaUZIZW93Q0RwOTFxSUZXZVJPQStXQ0xvZFUwNnErL0Q2dUNOZ05YWnQrYzZRRmZlS0Z6SDY3OUpSL3RJbmRUdGZHMjNIMmc4K2NQSzBCUjRsQWdrVVBiVTJkUWZUV3RucGdKRG1mdlhKcU9CeUErRGl3YmgxM0xQZnVoMWI5cU00OWUvc05UR2Nla0tqeUNJRmpMd1BpOE1LR3B6czN1ZjlZUkxOM3gyajR6Z1pxQlN6R0RyZzJkYnlGMkNGL1FSRGlCK1VwbTFMcXgwS1QvQ2hGMjMvYUFOR0F0THNYcHJzTWNXU0ZMalMwOVVJQlZlcHNIZXVET0lpaXl1WExQM1U0MVgyU0ZaU01NbkwxSE1QNXVmZGhMUTF0RTJKWWlRQ2haVUlPWkxqTjdYeSs1d2F6QmxFWmxkNHdxWDBRTmwxc2p3QXZFQWhSQThPNTVWOFRkaTVaL1kyQnhBeTg0WUJwZlltU2tDaGg5UnBGRkxNRkdtWnBJS0VJa0Z3YkRVZmNpeDlhQkJKaTFRbEJ5UG1welFoN1BpbG1lY0c1ZkZzcWoxKzNOWTRNMVBRalVYOHFWdVJLaXBlbGRlYWxZcFhtMHBteUxJOURNTXFnaWE2Syt0QVFBL0lLdWpoMWo0M2JDVzRzY1FqVnUvekh4UndFOW1IRmZOckkyY24rQmV1Qm9GZElwMEFGbkxUVHRqL3J3eUduM2Z6RTlmUGV0MTd2ZHdhK3ovLzN3a3lOdk9JUFBBSG1pZFVCTFdnRHIrNk8xb1NIWlpNTG1LRTE4bmZUYzBabEZGNmF4TXB0OWRLTHpZQ0lwdlFXWnJkWTVKVkord3QzMG44OUNVRWJxYz0ifSwiaWF0IjoxNzQ5ODEwMDA2fQ\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzM4NCJ9\",\"signature\":\"rvPkYyrozEsuSzTnMTNqeC4AJyG72yxVlfm2ruGWwZRhPSzKBGFJCcsVmK8aijHw82BVgPOAEFwSbTKyRq_972W1ZHokiZLdzUHpeVgEGlIxcDfaK6h600eD7279Oitm\"},{\"protected\":\"eyJhbGciOiJNTC1EU0EtNjUifQ\",\"signature\":\"2f-wtkSVuwAvwwQYWuMEVSJXDWNVMPo8NzyAZsazWjgWezAW7n6ad4CAuBObvREaluXwiq1wqauVLLr7XOQM-BugIIymudZjK-DxM1SUFivgY1S5neYnX-mXI3_TxT8p9eMYDGuNiL2jG9V-nyAYFXV_kCF06W5p9kw8FEotZMJc6fLKJSuZgB51jPp8dWg0lSUEXeQf1vniovYnbuMGgK-MYX7vN8HxUlNnrGheydaU33JjtEHmv9oxnEyYb31aV47DCRlrTeTXPGJljQ8CWCdGxnB_v5HaN_B6-qc4neVjhkn2G3mrzlcJlFkHTajwOc1nG8P2IUB_tEaAV3ZwDnwxxH7rUfAGDun0BanlU42H2O_J3_wtdypUN1mmsdx81p2zdHuWGT7zDkTmKyjHdjDMDCRjbqpm7_fhbNj70iMEkSBiTyoQa4Ki_CliVKzvt4UoM6ZicGA-gN0bvFk87IJrT9dR_9luKQ17jhHlPLWH-K0n4LnDEgqaDPli2ykE42DGPKhGZfUyRjtD-t3XElIgRJ_Jkiq6bGCY1gxrVe1jgyUIS20PHgDigo-pvXmelfxfqD4Fb4SiagGcKOGwzNGwGMWClROt5YgoRBXPkSe_B7P1kx1JtyiGQGyVdKtzX9WOtfsnU02rJfwVrwtjWBOdbbDlgOuFlWw7rrpIsbW86wlQ1Q3pXyupvoyLKZDB1AJY2XDVedrWTtFZ_2h-v7yFr-7BTypZ0mUftu3DUgfhRFHmnXOfKIQlC1VFCvQ8kxkVSS3XoSc7sV6a5k10tfevS4uufxGYcK9_KmKst-78GA5lcJapR4sp_F0g0oXopydKds7omnZX44b5E39Qs0j8ipPK9Z_dQUdHfgL9xZs7uGucJt1QV9q-66rN4lzwGqiLbXyE1OCwRqpxQnKjYnIr9hs6Z3EmRmnOK959lIKhRyTJya2fRyNxkqHjinPqkwuBQYLyOemk7kUhArCxhuHr3Fa3TzdpgUk9GGAPt3lMLIUJbNlcbVGYpJ_rNSRLbBDbBpjI1-WVwp0LKMssHUoWRZC3K7AyqCHNoOyYtCcBHHMtmUP3Rht-WmnoAJBeymSh7XrcnHwrPsK983PWua4kEq0N41QzFySOH4C96lEOjQOTcUjwXK1P7rRuVmlv4_S5GPG-CkKIDP_3Js_EqrnN29GT5vnpclwHTnQE7Tn0QwCESBjskKLKhA_Zoja29OEwhzmaYfopikpjrMgMrQpJTJqr2KoB7kf6I4AjYsKN9BoYQ1fvsBE23xg3Fra0S-nWNva-xgU0qF1lEFNdya-QRh-S1eqOf0vIW1WkW_NMQLmkgzw2SMHmu7nack5nZjTw47glb9_YS6mjD-jx03wXxU4WKf9qV6862-DmY0x4SRzlfEUylIdvB2JYJhjhR-Pih9RsLq9RA9Tdv377XwHzT77b8o0ooo1h76zmTlgBuxO4N65yAKOAerpHyQ0TwJ90e0onZO0k2YCic6GewYgsuF9kQi2_Wt6Z9ZQQFJ0A4TXG_dGrmSFDACNhDGrlljPv-Tp1YeCNwS8HAD7K-UTsYHBoB72oplz53jzWSiwZrDcMjR33xhZ3OuQY9FsmaNcwnM6fDWpRWOOaYHUlEOK3d6silxyLLXVBC5s4iWXStyfVvZZVukz4h12dgk3DANlAQFb-ZzGcqvj1wI48OkPTubWEXhEJKXQyksvUbFIdLpEePKo--Np4dwBFKYD1LQKLB0bnAqwPW7RapimlScsTcWNduW-Q3jv_OPL9qwpGoAjnLqHgzud9OO1qgcUhJowP51vP9hh-1LBoL535Dwh_zk11ewJ8hZopFHjBcnodX0YltA5Fw5B6FBS7iKCzZl-Yo1zi20qGwXmRCl4ROy5uNX_ECmg3qrWL6C6kVmXCHzRdd9dw1xVYhs_L6jDWhzeEmC_62eH0Hpb9lHISbdh2WH82V3VDYIoZQEwnRk_9gsXVzKnJ5ScAwl1tWaEgwzPJq5evkla6_4QRQlVx07Cnn_gCfhjq5P23ZX_ThP7SLxFZ2rnUZ8xIBiawocHo9v35RsJ83oKitK75XURNmn9IAtZQb1fI3NxcV-jN1HongMRwtUqIpvo-nF-M8P2MiLyMvS6XQHW5VqCpa_35xr4YSL8Mv7VZ2q7dorcoP4pTopZMZz16o-aIeUhYns1xcy-6jBu3ZUuXkYlkzVWt8HnZY5bm2UdjOSr2isNH3yCgU2Ku_pL8jxoP-KhvsdJxtAx8-sJQACBOz7czsfrY-gux7GS338YRoutKqAOQu9ey-9-CEl-RBHEYgGvR67UsPfFSEAazJ6e-NNiyNwr89-sox1j8KytBYuk1LBuzMoz0SA8WSaiAzFh0c7zwYRokj0OYYPJs0jk7_FkuX6x5KMmR-ZPhmZZMAzmqpa4f4fQYtiG0gF36glnUh0awg3VYCACRnRelegU8nvcyBm49_yfiywn2iHUkPrqGr2osNKuXurygNAKgTqkM3tvbbGbx93rKbwNLJPxf_6VQlTmggXROESyOhDTgLebcWGx_AZQCtKPF2vEL7hr0eJH2QaTkiHcO92g7oDvY_ARX2-hce3MORNpOdWb6TvUdC7HIIsDBaYW-2DRsXtNuclF6xl9_BwxQ_IYXQFkfTA6J6mUEZcrOOUCKN0klj5Tpf9kGjht-aeGy5IWqDmyhkAMrfInrFgNGJWY4wG2TqNy6bnU_THTVMUZ6LXgN8qPqi2YZWn5BJpE7Q1q1-mcIsuecAvDbdokkWKqID-71ibXLF80VcqRvj3TzTkl2ySzb8SyNQ9nvGZBN3hLElBNq4d27zja2SJ0KdBtiDQhcaZCmyPl3kkSUge9kuYKBoWEY_R6jwkB1mNS_ZqIROvycaaRVdHUjrwj4Vk8VRlN9dziyiE2rTEIIAdk4anf5Yzk1c8JOyWYG_5SbGRkU93oHHP4sJFZX_g-SOHGyAAxMYO4WNGMCbqD5mC1bVIXxEkyJRT3IQCXEtq1lb-zG2099Sxcsro8KvnC4zxtLVbx69GMKB-RuIo-_EQ0AcfDmdWxYkWUqeuzcFTx4PR_43zIX4aiJeMOT1uKjoKm2i7hRTu4os_AiIyUtUwtPxPK9hza-Xm_zHnwZyCLQC5QfchZGmmhb3ADpewfEgAEcJeAasTFgklwcj5a1kpTMz7eykvEIBzoTSG-76X3XPRz4X_XBTnrgeg29BRR-fHCGZiCIovCMbivMcyDgtCQGOgc4PDJRd91f6ud8RbqU9QJZJBh6k3TjtiKv80aDIDVQIi8IvxICBP61K84r5Z6CZ8BQ457Iu-CX-xoEzhPhX30OkzYpEQy4CeNMVs6YerGUtgTJMOoZ6HzURjk5CSIh8b71CUj_cY6xk1CO1-W8Uof1aNGTUnAN_hG4WpSX1KhpRP76v_luIdrV3pJ0n0eU2HzYBgkrpCVup1E5dJfij1uOaHfHs2VzSeTAukD10Ty-yvGv7Zv3WTrjbNFNWVDKQfZqZmavgKOslsxAA336gJv4K78cOv0d8C3hDlOiO0fQDMJn7GwATem7Hs0nLzQy5qrtZ-_xg6FkjLe0LPkSHqzi1oONLXs0F0O-C3jc9AGaqLmyt33j8c5S0HsD8Q3uu_kGKdwQlINuCqr4-8IpzogO4yLTJ5J_spUH3g7Yt_fpOtWbg6FnK7aB_CiokUhgMBvPvtCpirijYapK-aA9lPwwW5jxEkCYb9trPRAMuBJnAgmiet7KbzO8rWDzhNsbBEIdVSd3cNIqo3Wg_c9mF9iZ3THOAbrI2ASIdqjFdqyfOc5_y3lE1qI4WWst9Sb0sgHNVLN-FPptR59Y_ai7b2-yJPvDhkJWZHYiiJis5AETpV0h6QeowOrOAzqvnOKWiQZXtZYjp69K57L4oP7gmNPYkEilxj7OpSboPrwOWvtSHdbZomgziHUz904ve6_dCfzmQYnmwlqGKnyh410E0CcDI8Ex8YgpouVIWE4S16UvIqsqIlJXEo_MrpP-4GVvuIYYYpE9LqksSiGRrTMp1QaEDq8kCTK0ldkDJwxvaWb5pxqPj5z8x0tsyeZqn-Q-cVbPBV8xD_52Zqc-HXE2rZiVeTbz9Ab4rUpg7PvKB8Ed7-TC99ptiR6YoAuJBlc_u3QEykkksD9TeHllZnQhmjSwERifuMgyk8CTxErMESbv-Zx244E0E3YxeMwiqVEkA1iRfgZSO3AJaBVqB6sHTCR_f0k0tSmicH_JR8drKHMz5zc3oCrfdw2Bej4ObFuSZm8_uOp3uUot1Fm3mrF0HIOtri6U4w0-NrSkgqgjMDqnmokm4ELajjSweUX38JvtSszhA1lql2D2IJs4O1JkoiI3PU5VXGeTp9JCrbbe-_6f5wYSRpTd5_8RGztQcn-PsPT8_wAAAAAAAAAAAAAAAAAABQ8VFx4p\"}]}",
                    {
                        JwsKey::publicKey(publicKey("P-384", "BG/pz6Gomet1gaEhki+xcaWM4gPs119wG7MpjsmlryuuUqQ5l/qia6vrjpDUDGCpp1VmiGambEl42k1bDeNBPhUQW/lZxoVZQeQrBwJjF++AyP4P5vXxQ3hOUYRrpKCjmg==", crypto::KEY_FORMAT_X963)),
                        JwsKey::publicKey(publicKey("ML-DSA-65", "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"))
                    },
                    TEST_OK
                }
            };
            for (const auto& td : composite_vectors) {
                auto reader = JwtReader::fromJsonString(td.signature);
                try {
                    reader.verify(td.keys);
                    if (td.testMode == TEST_FAIL) {
                        ccstFailure("Validation should fail");
                        break;
                    }
                } catch (JwtException & e) {
                    if (td.testMode != TEST_FAIL) {
                        ccstFailure("Validation failed");
                        break;
                    }
                }
            }
        }
        
        struct SignVerifyData
        {
            std::string jws_name;
            JwsKeyPtr sign_key;
            JwsKeyPtr verify_key;
        };
        
        SignVerifyData testDataForDsa(const std::string& alg_name)
        {
            auto key_pair = crypto::KeyPair::generateKeyPair(alg_name);
            return {
                JwsSpec::specForKeyAlgorithm(alg_name)->jwsName,
                JwsKey::privateKey(key_pair->getPrivateKeyPtr()),
                JwsKey::publicKey(key_pair->getPublicKeyPtr()),
            };
        }
        
        SignVerifyData testDataForMac(const std::string& alg, size_t size)
        {
            auto key = crypto::GetRandomData(size);
            return {
                alg,
                JwsKey::symmetricKey(alg, key),
                JwsKey::symmetricKey(alg, crypto::SymmetricKey::getInstance(key))
            };
        }
        
        struct MultiSignVerifyData
        {
            std::string title;
            JwsKeyList sign_keys;
            JwsKeyList verify_keys;
        };
        
        bool isMacAlg(const std::string& algorithm)
        {
            auto spec = JwsSpec::specForJwsAlgorithm(algorithm);
            return spec ? spec->type == JwsSpec::Type::MAC : false;
        }
        
        MultiSignVerifyData testDataForAlgs(const std::vector<std::string>& algs)
        {
            std::string title;
            JwsKeyList sign, verify;
            for (auto alg : algs) {
                SignVerifyData td;
                if (isMacAlg(alg)) {
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
                for (auto iter = 1; iter <= 2; iter++) {
                    std::string iter_name = iter == 1 ? "JWT" : "";
                    ccstMessage("%s", td.sign_key->getJwtAlgorithm().c_str());
                    auto jwt = JwtWriter()
                        .withPayload(payload, iter_name)
                        .sign({ td.sign_key })
                        .toCompact();
                    auto parsed = JwtReader::fromCompact(jwt)
                        .verify({ td.verify_key })
                        .getPayload();
                    auto claims = JsonReader::fromJsonData(parsed);
                    ccstAssertEqual("1234567890", claims["sub"].asString());
                    ccstAssertEqual("John Doe", claims["name"].asString());
                    ccstAssertEqual(true, claims["admin"].asBoolean());
                    ccstAssertEqual(1516239022, claims["iat"].asInteger());
                    // verify signature manually
                    auto pos = jwt.rfind('.');
                    ccstAssertNotEqual(std::string::npos, pos);
                    auto signed_data = ByteArray(MakeRange(jwt.substr(0, pos)));
                    auto signature   = Base64::urlDecode(jwt.substr(pos + 1));
                    auto spec = JwsSpec::specForJwsAlgorithm(td.jws_name);
                    bool verified = false;
                    switch (spec->type) {
                        case JwsSpec::Type::MAC: {
                            crypto::ParameterList params;
                            if (spec->sizeParam) {
                                params[crypto::MAC_PARAM_DIGEST_LENGTH] = crypto::Parameter::take(spec->sizeParam);
                            };
                            if (!spec->stringParam.empty()) {
                                params[crypto::MAC_PARAM_CUSTOM_STRING] = crypto::Parameter::ref(spec->stringParam);
                            }
                            const auto& key = td.sign_key->getSymmetricKey();
                            auto mac_algorithm = crypto::MAC::getInstance(spec->algorithm);
                            verified = mac_algorithm->verifyToken(key, signed_data, signature, params);
                            break;
                        }
                        case JwsSpec::Type::DSA: {
                            if (spec->inputConversion) {
                                signature = spec->inputConversion(spec, signature);
                            }
                            const auto& key = td.verify_key->getPublicKey();
                            auto dsa_algorithm = crypto::Signature::getInstance(spec->algorithm);
                            verified = dsa_algorithm->verify(key, signature, signed_data);
                            break;
                        }
                    }
                    if (!verified) {
                        ccstMessage("JWT   %s", jwt.c_str());
                        if (spec->type == JwsSpec::Type::MAC) {
                            ccstMessage("Key   %s", td.verify_key->getSymmetricKey().getKeyData().base64Url().c_str());
                        } else {
                            ccstMessage("Key   %s", td.verify_key->getPublicKey().exportKey().base64().c_str());
                        }
                        ccstMessage("Verification failed for '%s'", iter_name.c_str());
                    }
                    ccstAssertTrue(verified);
                }
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
            tests.push_back(testDataForAlgs({ "ML-DSA-65", "HS512" }));
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
