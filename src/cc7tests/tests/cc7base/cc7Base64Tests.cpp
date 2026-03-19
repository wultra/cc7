/*
 * Copyright 2016 Juraj Durech <durech.juraj@gmail.com>
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
#include <cc7/CC7.h>

namespace cc7
{
namespace tests
{
    class cc7Base64Tests : public UnitTest
    {
    public:
        cc7Base64Tests()
        {
            CC7_REGISTER_TEST_METHOD(testEncodeDecode);
            
            CC7_REGISTER_TEST_METHOD(testBase64DecoderTable);
            CC7_REGISTER_TEST_METHOD(testBase64UrlDecoderTable);

            CC7_REGISTER_TEST_METHOD(testNoWrap);
            CC7_REGISTER_TEST_METHOD(testNoWrapBadData);
            
            CC7_REGISTER_TEST_METHOD(testUrl);
            CC7_REGISTER_TEST_METHOD(testUrlBadData);
            
            CC7_REGISTER_TEST_METHOD(testWrap);
            CC7_REGISTER_TEST_METHOD(testWrapBadData);
        }
        
        // UNIT TESTS
        
        void testEncodeDecode()
        {
            // Good scenarios
            ByteArray max_data = getTestRandomData(1025);
            for (size_t test_size = 0; test_size < max_data.size(); test_size++)
            {
                ByteRange source_data = max_data.byteRange().subRangeTo(test_size);
                std::string plain, padded64, padded76;
                ByteArray plain_dec, padded64_dec, padded76_dec;
                
                // classic
                plain        = Base64::encode(source_data, Base64::NONE);
                padded64     = Base64::encode(source_data, Base64::WRAP_64);
                padded76     = Base64::encode(source_data, Base64::WRAP_76);
                plain_dec    = Base64::decode(plain,       Base64::NONE);
                padded64_dec = Base64::decode(padded64,    Base64::WRAP_64);
                padded76_dec = Base64::decode(padded76,    Base64::WRAP_76);
                ccstAssertEqual(source_data, plain_dec);
                ccstAssertEqual(source_data, padded64_dec);
                ccstAssertEqual(source_data, padded76_dec);
                
                // url
                plain        = Base64::urlEncode(source_data);
                plain_dec    = Base64::urlDecode(plain);
                ccstAssertEqual(source_data, plain_dec);
            }
        }
                
        void testBase64DecoderTable()
        {
            ByteArray out;
            // Check if internal decoder table is correct
            const char * valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string valid("SGVs");
            for (int i = 0; i <= 0xff; i++) {
                // inject wrong character...
                std::string wrong = valid;
                if (strchr(valid_chars, i) != NULL) {
                    // this is valid character
                    continue;
                }
                byte uc = i & 0xff;
                wrong[ 0 ] = uc;
                try {
                    out = Base64::decode(wrong, 0);
                    ccstFailure("Should fail");
                } catch (...) {}
                wrong[ 0 ] = 'x';
                wrong[ 1 ] = uc;
                try {
                    out = Base64::decode(wrong, 0);
                    ccstFailure("Should fail");
                } catch (...) {}
                wrong[ 1 ] = 'x';
                wrong[ 2 ] = uc;
                try {
                    out = Base64::decode(wrong, 0);
                    ccstFailure("Should fail");
                } catch (...) {}
                if (uc == '=') {
                    // Next validation makes no sense if injected char is padding marker
                    continue;
                }
                wrong[ 2 ] = 'x';
                wrong[ 3 ] = uc;
                try {
                    out = Base64::decode(wrong, 0);
                    ccstFailure("Should fail");
                } catch (...) {}
            }
        }
        
        void testBase64UrlDecoderTable()
        {
            ByteArray out;
            // Check if internal decoder table is correct
            const char * valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            std::string valid("SGVs");
            for (int i = 0; i <= 0xff; i++) {
                // inject wrong character...
                std::string wrong = valid;
                if (strchr(valid_chars, i) != NULL) {
                    // this is valid character
                    continue;
                }
                byte uc = i & 0xff;
                wrong[ 0 ] = uc;
                try {
                    out = Base64::urlDecode(wrong);
                    ccstFailure("Should fail");
                } catch (...) {}
                wrong[ 0 ] = 'x';
                wrong[ 1 ] = uc;
                try {
                    out = Base64::urlDecode(wrong);
                    ccstFailure("Should fail");
                } catch (...) {}
                wrong[ 1 ] = 'x';
                wrong[ 2 ] = uc;
                try {
                    out = Base64::urlDecode(wrong);
                    ccstFailure("Should fail");
                } catch (...) {}
                if (uc == '=') {
                    // Next validation makes no sense if injected char is padding marker
                    continue;
                }
                wrong[ 2 ] = 'x';
                wrong[ 3 ] = uc;
                try {
                    out = Base64::urlDecode(wrong);
                    ccstFailure("Should fail");
                } catch (...) {}
            }
        }

        void testNoWrap()
        {
            // Fixed scenarios
            std::string str1("SGVsbG8gd29ybGQ=");
            std::string str2("SGVsbG8gd29yZA==");
            std::string str3("SGVsbG9+d29ybGQh");
            std::string str4("Kyc/dm9hbC1eQg==");
            
            std::string out_str = CopyToString(Base64::decode(str1));
            ccstAssertEqual(out_str, "Hello world");
            
            out_str = CopyToString(Base64::decode(str2));
            ccstAssertEqual(out_str, "Hello word");
            
            out_str = CopyToString(Base64::decode(str3));
            ccstAssertEqual(out_str, "Hello~world!");
            
            out_str = CopyToString(Base64::decode(str4));
            ccstAssertEqual(out_str, "+'?voal-^B");
        }
        
        void testNoWrapBadData()
        {
            ByteArray out;
            std::vector<std::string> bad_data {
                "SGVsbG9-d29ybGQh",
                "Kyc_dm9hbC1eQg=="
                "SGVsbG8gd29ybGQ",
                "SGVsbG8gd29yZA=",
                "SGVs_G8gd29ybGQ=",
                "SGVsbG8gd29y?A==",
                "SGVsbG8gd29ybA=X",
                "SGVsbG8gd29yb===",
                "SGVsbG8gd29y====",
                "SGV=bG8gd29ybGQ=",
                "SGVsbG8gd29yZA==\n",
                " SGVsbG8gd29yZA==",
            };
            for (auto data : bad_data) {
                try {
                    auto out = Base64::decode(data);
                    ccstFailure("Should fail: %s", + data.c_str());
                } catch (std::domain_error& e) {
                    // OK
                } catch (...) {
                    ccstFailure("Unexpected exception: %s", + data.c_str());
                }
            }
        }
        
        void testUrl()
        {
            // Fixed scenarios
            std::string str1("SGVsbG8gd29ybGQ");
            std::string str2("SGVsbG8gd29yZA");
            std::string str3("SGVsbG9-d29ybGQh");
            std::string str4("Kyc_dm9hbC1eQg");
            std::string str5("eyJ0ZXh0Ijoixb7DtMW-w6QifQ");

            std::string out_str = CopyToString(Base64::urlDecode(str1));
            ccstAssertEqual(out_str, "Hello world");
            
            out_str = CopyToString(Base64::urlDecode(str2));
            ccstAssertEqual(out_str, "Hello word");
            
            out_str = CopyToString(Base64::urlDecode(str3));
            ccstAssertEqual(out_str, "Hello~world!");
            
            out_str = CopyToString(Base64::urlDecode(str4));
            ccstAssertEqual(out_str, "+'?voal-^B");
            
            out_str = CopyToString(Base64::urlDecode(str5));
            ccstAssertEqual(out_str, u8"{\"text\":\"žôžä\"}");
        }

        void testUrlBadData()
        {
            ByteArray out;
            std::vector<std::string> bad_data {
                "SGVsbG8gd29ybGQ=",
                "SGVsbG8gd29yZA==",
                "SGVsbG9+d29ybGQh",
                "Kyc/dm9hbC1eQg==",
                "SGVsbG8gd29yZA=",
                "SGVs_G8gd29ybGQ=",
                "SGVsbG8gd29y?A==",
                "SGVsbG8gd29ybA=X",
                "SGVsbG8gd29yb===",
                "SGVsbG8gd29y====",
                "SGV=bG8gd29ybGQ=",
                "SGVsbG8gd29yZA==\n",
                " SGVsbG8gd29yZA==",
            };
            for (auto data : bad_data) {
                try {
                    auto out = Base64::urlDecode(data);
                    ccstFailure("Should fail: %s", + data.c_str());
                } catch (std::domain_error& e) {
                    // OK
                } catch (...) {
                    ccstFailure("Unexpected exception: %s", + data.c_str());
                }
            }
        }

        void testWrap()
        {
            std::string input("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np\n"
                               "bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFi\n"
                               "b3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVu\n"
                               "aWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBu\n"
                               "aXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0\n"
                               "ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxp\n"
                               "dCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBF\n"
                               "eGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBz\n"
                               "dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlk\n"
                               "IGVzdCBsYWJvcnVtLg==");
            const char * expected_output =  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do"
                                            " eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut"
                                            " enim ad minim veniam, quis nostrud exercitation ullamco laboris"
                                            " nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor"
                                            " in reprehenderit in voluptate velit esse cillum dolore eu"
                                            " fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
                                            " proident, sunt in culpa qui officia deserunt mollit anim id"
                                            " est laborum.";
            ByteArray output_data;
            output_data = Base64::decode(input, 64);
            std::string output = CopyToString(output_data);
            ccstAssertEqual(expected_output, output);
            
            input.insert(0, "\n");
            input.append("\n");
            output_data = Base64::decode(input, 64);
            output = CopyToString(output_data);
            ccstAssertEqual(expected_output, output);
            
            input = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np";
            output_data = Base64::decode(input, 64);
            output = CopyToString(output_data);
            ccstAssertEqual("Lorem ipsum dolor sit amet, consectetur adipisci", output);
            
            input = "                            TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np                         ";
            output_data = Base64::decode(input, 64);
            output = CopyToString(output_data);
            ccstAssertEqual("Lorem ipsum dolor sit amet, consectetur adipisci", output);

            input = "\n\n  \nTG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np\n\n  \n\n\n";
            output_data = Base64::decode(input, 64);
            output = CopyToString(output_data);
            ccstAssertEqual("Lorem ipsum dolor sit amet, consectetur adipisci", output);
            
            input = "\nTG9y\nZW0g\naXBz\ndW0g\nZG9s\nb3Ig\nc2l0\nIGFt\nZXQs\nIGNv\nbnNl\nY3Rl\ndHVy\nIGFk\naXBp\nc2Np\n\n";
            output_data = Base64::decode(input, 64);
            output = CopyToString(output_data);
            ccstAssertEqual("Lorem ipsum dolor sit amet, consectetur adipisci", output);
            
            // various non empty strings leading to empty data
            input = "                                    ";
            output_data = Base64::decode(input, 64);
            ccstAssertEqual(output_data.size(), 0);
            input = " ";
            output_data = Base64::decode(input, 64);
            ccstAssertEqual(output_data.size(), 0);
            input = "  ";
            output_data = Base64::decode(input, 64);
            ccstAssertEqual(output_data.size(), 0);
            input = " \t ";
            output_data = Base64::decode(input, 64);
            ccstAssertEqual(output_data.size(), 0);

            input = "";
            output_data = Base64::decode(input, 64);
            ccstAssertEqual(output_data.size(), 0);
        }
        
        void testWrapBadData()
        {
            std::string input;
            ByteArray output_data;
            try {
                input = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2N\n"
                        "bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbG==\n";
                output_data = Base64::decode(input, 64);
                ccstFailure("Should fail");
            } catch (std::domain_error & e) {
                // expected
            } catch (...) {
                ccstFailure("Unexpected exception");
            }
            try {
                input = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2N=\n"
                        "bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbG==\n";
                output_data = Base64::decode(input, 64);
                ccstFailure("Should fail");
            } catch (std::domain_error & e) {
                // expected
            } catch (...) {
                ccstFailure("Unexpected exception");
            }
        }
    };
    
    CC7_CREATE_UNIT_TEST(cc7Base64Tests, "cc7")
    
} // cc7::tests
} // cc7
