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

class cc7CryptoImportKeyTests : public UnitTest
{
public:
    cc7CryptoImportKeyTests()
    {
        CC7_REGISTER_TEST_METHOD(testKeyImport);
    }
    
    static bool stringHasPrefix(const std::string & str, const std::string & prefix)
    {
        return str.size() >= prefix.size() &&
               str.compare(0, prefix.size(), prefix) == 0;
    }

    // UNIT TESTS
        
    void testKeyImport()
    {
        auto root = JSON_ParseFile(g_testFiles, "test-data/key-import-data.json");
        auto && data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto algorithm = item.stringAtPath("alg");
            auto type = item.stringAtPath("type");
            auto keyFmtStr = item.stringAtPath("fmt");
            auto keyFmt = crypto::KeyFormat_FromString(keyFmtStr);
            auto keyData = item.dataFromBase64StringAtPath("data");
            auto expected_result = item.containsValueAtPath("result") ? item.stringAtPath("result") : "ok";
            
            ccstMessage("%s (%s), fmt: %s", algorithm.c_str(), type.c_str(), keyFmtStr.c_str());
            
            std::string result = "ok";
            do {
                crypto::KeyPtr key;
                // create instance
                try {
                    if (type == "public") {
                        key = crypto::PublicKey::getInstance(algorithm);
                    } else if (type == "private") {
                        key = crypto::PrivateKey::getInstance(algorithm);
                    } else if (type == "symmetric") {
                        key = crypto::SymmetricKey::getInstance(algorithm);
                    } else {
                        result = "wrong test data";
                        break;
                    }
                } catch (std::exception & e) {
                    result = "wrong type";
                    break;
                }
                
                try {
                    key->importKey(keyData, keyFmt);
                } catch (std::exception & e) {
                    result = "import fail: " + std::string(e.what());
                    break;
                }                
                bool export_fail = false;
                for (const auto & e_item : item.arrayAtPath("export")) {
                    auto expFmtStr = e_item.stringAtPath("fmt");
                    auto expFmt = crypto::KeyFormat_FromString(expFmtStr);
                    bool should_success = e_item.containsValueAtPath("data");
                    auto dup_key = key->duplicate();
                    try {
                        if (e_item.containsValueAtPath("fmt2")) {
                            dup_key->setKeyParameter(crypto::KEY_PARAM_EC_POINT_CONVERSION, crypto::Parameter::from(e_item.stringAtPath("fmt2")));
                        }
                        auto data = dup_key->exportKey(expFmt);
                        if (!should_success) {
                            export_fail = true;
                            result = "export should fail for " + expFmtStr;
                            break;
                        }
                        if (data != e_item.dataFromBase64StringAtPath("data")) {
                            export_fail = true;
                            result = "unexpected exported data (" + expFmtStr + "): " + data.base64String() + " vs " + e_item.stringAtPath("data");
                            break;
                        }
                    } catch (std::exception & e) {
                        if (should_success) {
                            export_fail = true;
                            result = "export should not fail: " + std::string(e.what());
                            break;
                        }
                    }
                }
                if (export_fail) {
                    break;
                }
                
                if (item.containsValueAtPath("badFmt")) {
                    for (const auto & bad_format : item.arrayAtPath("badFmt")) {
                        try {
                            auto bad_fmt_str = bad_format.asString();
                            auto bad_fmt = crypto::KeyFormat_FromString(bad_fmt_str);
                            key->importKey(keyData, bad_fmt);
                            result = "should not import data in " + bad_fmt_str;
                            break;
                        } catch (std::exception & e) {
                            // ignore
                        }
                    }
                }

            } while (false);
            

            if (!stringHasPrefix(result, expected_result)) {
                ccstMessage("   - expected : %s", expected_result.c_str());
                ccstMessage("   - result   : %s", result.c_str());
                
                ccstFailure("%s I/O is broken", algorithm.c_str());
                break;
            }
        }
    }
};

CC7_CREATE_UNIT_TEST(cc7CryptoImportKeyTests, "cc7")
    
} // cc7::tests
} // cc7
