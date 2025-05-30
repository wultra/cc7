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
#include <cc7/json/JsonWriter.h>

using namespace cc7::json;

namespace cc7
{
namespace tests
{
    extern TestDirectory g_testFiles;
    
    class JsonWriterTests : public UnitTest
    {
    public:
        JsonWriterTests()
        {
            CC7_REGISTER_TEST_METHOD(testSimpleWrite)
            CC7_REGISTER_TEST_METHOD(testComplexWrite)
        }
               
        // UNIT TESTS
        struct SimpleData {
            JsonValue value;
            std::string expected_compact;
            std::string expected_pretty;
        };

        void testSimpleWrite()
        {
            auto empty_array  = JsonValue::array();
            auto empty_object = JsonValue::object();
            const std::vector<SimpleData> data {
                { empty_array, "[]", "[\n]" },
                { empty_object, "{}", "{\n}" },
                { JsonValue((int64_t)4), "4" },
                { JsonValue((int64_t)1000), "1000" },
                { JsonValue(6.43), "6.42999999999999972e+00" },
                { JsonValue(-3e-17), "-3.00000000000000006e-17" },
                { JsonValue(1203.0), "1.20300000000000000e+03" },
                { JsonValue(2580001.0), "2.58000100000000000e+06" },
                { JsonValue(128000000000004.0), "1.28000000000004000e+14" },
                { JsonValue(true), "true" },
                { JsonValue(false), "false" },
                { JsonValue::null(), "null" },
                { JsonValue(), "null" },
                { JsonValue("Hello world!"), "\"Hello world!\"" },
            };
            
            auto compact = JsonWriter();
            auto pretty = JsonWriter(JsonWriter::PrettyOutput);
            auto reader = JsonReader();
            for (const auto& td : data) {
                auto expected_compact = td.expected_compact;
                auto expected_pretty = td.expected_pretty.empty() ? expected_compact : td.expected_pretty;
                auto out_compact = compact.toString(td.value);
                auto out_pretty = pretty.toString(td.value);
                auto from_compact = reader.fromJsonString(out_compact);
                auto from_pretty  = reader.fromJsonString(out_pretty);

                ccstAssertEqual(expected_compact, out_compact);
                ccstAssertEqual(expected_pretty, out_pretty);
                
                if (expected_compact != out_compact) {
                    ccstMessage("Compact: %s vs %s", expected_compact.c_str(), out_compact.c_str());
                }
                if (expected_pretty != out_pretty) {
                    ccstMessage("Pretty: %s vs %s", expected_pretty.c_str(), out_pretty.c_str());
                }
                if (td.value.isValid()) {
                    ccstAssertEqual(td.value, from_compact);
                    ccstAssertEqual(td.value, from_pretty);
                    if (td.value != from_compact) {
                        ccstMessage("Compact reexport: %s", out_compact.c_str());
                    }
                    if (td.value != from_pretty) {
                        ccstMessage("Pretty reexport: %s", out_pretty.c_str());
                    }
                }
            }
        }
        
        void testComplexWrite()
        {
            auto root = JSON_ParseFile(g_testFiles, "test-data/json-complex.json");
            
            auto pretty_writer = JsonWriter(JsonWriter::PrettyOutput | JsonWriter::KeepNull);
            auto compact_writer = JsonWriter(JsonWriter::KeepNull);
            auto double_loss_writer = JsonWriter(JsonWriter::KeepNull | JsonWriter::NiceDouble);
            
            auto exported = pretty_writer.toString(root);
            auto imported = JsonReader::fromJsonString(exported);
            ccstAssertEqual(root, imported);
            
            exported = compact_writer.toString(root);
            imported = JsonReader::fromJsonString(exported);
            ccstAssertEqual(root, imported);
            
            exported = double_loss_writer.toString(root);
            imported = JsonReader::fromJsonString(exported);
            // No doubles in original JSON, so we can compare values directly
            ccstAssertEqual(root, imported);

            
            root = JSON_ParseFile(g_testFiles, "test-data/json-simple.json");
            simpleJsonValidation(root, "original");
            exported = pretty_writer.toString(root);
            imported = JsonReader::fromJsonString(exported);
            simpleJsonValidation(imported, "pretty");
            ccstAssertEqual(root, imported);
            
            exported = compact_writer.toString(root);
            imported = JsonReader::fromJsonString(exported);
            simpleJsonValidation(imported, "compact");
            ccstAssertEqual(root, imported);
            
            exported = double_loss_writer.toString(root);
            imported = JsonReader::fromJsonString(exported);
            simpleJsonValidation(imported, "double loss");
            ccstAssertFalse(root == imported);

        }
        
        void simpleJsonValidation(const JsonValue & root, const char * info)
        {
            ccstMessage("Validating %s", info);
            ccstAssertEqual(root.valueAtPath("key1").asString(), "value1");
            ccstAssertEqual(root.booleanAtPath("true"), true);
            ccstAssertEqual(root.booleanAtPath("false"), false);
            ccstAssertEqual(root.valueAtPath("empty").isNull(), true);
            ccstAssertEqual(root.valueAtPath("object").isType(JsonValue::Object), true);
            ccstAssertEqual(root.valueAtPath("array").isType(JsonValue::Array), true);
            
            ccstAssertEqual(root.stringAtPath("object.xxx"), "this is xxx");
            ccstAssertEqual(root.booleanAtPath("object.yyy"), false);
            ccstAssertEqual(root.integerAtPath("object.zzz.integer"), 64);
            ccstAssertEqual(root.doubleAtPath("object.zzz.double"), 6.4);
            ccstAssertEqual(root.stringAtPath("object.zzz.unicode1"), u8"Ľalie poľné");
            ccstAssertEqual(root.stringAtPath("object.zzz.unicode2"), u8"Ľalie poľné");
            
            auto&& array = root.arrayAtPath("array");
            ccstAssertEqual(array[0].asString(), "a");
            ccstAssertEqual(array[1].asString(), "b");
            ccstAssertEqual(array[2].asString(), "c");
            ccstAssertEqual(array[3].asBoolean(), true);
            ccstAssertEqual(array[4].isType(JsonValue::Object), true);
            ccstAssertEqual(array[5].isType(JsonValue::Object), true);
            ccstAssertEqual(array[6].isType(JsonValue::Object), true);
            
            auto&& array2 = array[4].arrayAtPath("sub-array");
            ccstAssertEqual(array2[0].asInteger(), 1);
            ccstAssertEqual(array2[1].asInteger(), 2);
            ccstAssertEqual(array2[2].asInteger(), 3);
            ccstAssertEqual(array2[3].asInteger(), 4);
            auto&& array3 = array[5].arrayAtPath("sub-array");
            ccstAssertEqual(array3[0].asDouble(), 1.1);
            ccstAssertEqual(array3[1].asDouble(), 2.2);
            ccstAssertEqual(array3[2].asDouble(), 3.3);
            ccstAssertEqual(array3[3].asDouble(), 4.4);
            auto&& array4 = array[6].arrayAtPath("sub-array");
            ccstAssertEqual(array4[0].asInteger(), -1);
            ccstAssertEqual(array4[1].asDouble(), -1.1);
            ccstAssertEqual(array4[2].asDouble(), 1e3);
            ccstAssertEqual(array4[3].asDouble(), 3.2e-1);
        }
    };
    
    CC7_CREATE_UNIT_TEST(JsonWriterTests, "cc7 test")
    
} // cc7::tests
} // cc7
