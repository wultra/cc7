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
#include <cc7/json/JsonValue.h>

using namespace cc7::json;

namespace cc7
{
namespace tests
{

class JsonValueTests : public UnitTest
{
public:
    JsonValueTests()
    {
        CC7_REGISTER_TEST_METHOD(testString)
        CC7_REGISTER_TEST_METHOD(testObject)
        CC7_REGISTER_TEST_METHOD(testArray)
        CC7_REGISTER_TEST_METHOD(testPrimitiveTypes)
        CC7_REGISTER_TEST_METHOD(testBytes)
        CC7_REGISTER_TEST_METHOD(testMove)
    }
    
    void testString()
    {
        auto val0 = JsonValue::string();
        auto val1 = JsonValue("hello world");
        auto val2 = JsonValue(std::string("hello world"));
        auto val3 = JsonValue(std::string("h3llo world"));
        ccstAssertEqual(std::string("hello world"), val1.asString());
        ccstAssertEqual("hello world", val2.asString());
        ccstAssertEqual(val1, val2);
        ccstAssertNotEqual(val0, val1);
        ccstAssertNotEqual(val3, val1);
        ccstAssertNotEqual(val3, val2);
        testCasting(JsonValue::String, { &val0, &val1, &val2, &val3 });
        
        // mutating
        val1.asMutableString().append("!!");
        ccstAssertEqual(std::string("hello world!!"), val1.asString());
    }
    
    void testObject()
    {
        auto val0 = JsonValue::object();
        auto val1 = JsonValue({
            { "boolKey", JsonValue::yes() },
            { "intKey", JsonValue::integer(4) }
        });
        auto val2 = JsonValue({
            { "intKey", JsonValue::integer(4) },
            { "boolKey", JsonValue::yes() }
        });
        auto val3 = JsonValue({
            { "intKey", JsonValue::integer(4) },
            { "boolKey", JsonValue::no() }
        });
        ccstAssertEqual(4, val1["intKey"].asInteger());
        ccstAssertEqual(true, val2["boolKey"].asBoolean());
        ccstAssertEqual(false, val3["boolKey"].asBoolean());
        ccstAssertEqual(val1, val2);
        ccstAssertNotEqual(val0, val1);
        ccstAssertNotEqual(val3, val1);
        ccstAssertNotEqual(val3, val2);
        testCasting(JsonValue::Object, { &val0, &val1, &val2, &val3 });
        
        // mutating
        val3["boolKey"].assign(true);
        ccstAssertEqual(val3, val2);
        
        ccstAssertFalse(val1["otherKey"].isValid());
        ccstAssertTrue(val1.containsValueAtPath("otherKey"));
        val1["otherKey"] = JsonValue::null();
        ccstAssertTrue(val1["otherKey"].isValid());
    }
    
    void testArray()
    {
        auto val0 = JsonValue::array();
        auto val1 = JsonValue({
            JsonValue("Hello World"), JsonValue::yes(), JsonValue::number(3.4)
        });
        auto val2 = JsonValue::array();
        val2.pushBack(JsonValue("Hello World"));
        val2.pushBack(JsonValue::yes());
        val2.pushBack(JsonValue::number(3.4));
        auto val3 = JsonValue({
            JsonValue("Hello World"), JsonValue::no(), JsonValue::number(3.4)
        });
        ccstAssertEqual(val1, val2);
        ccstAssertNotEqual(val0, val1);
        ccstAssertNotEqual(val3, val1);
        ccstAssertNotEqual(val3, val2);
        testCasting(JsonValue::Array, { &val0, &val1, &val2, &val3 });
        
        // mutating
        val3[1].assign(true);
        ccstAssertEqual(val3, val1);
    }
    
    void testPrimitiveTypes()
    {
        auto x = JsonValue::integer(4);
        auto y = JsonValue::count(4);
        auto z = JsonValue::count(5);
        ccstAssertEqual(x, y);
        ccstAssertNotEqual(x, z);
        ccstAssertNotEqual(y, z);
        testCasting(JsonValue::Integer, { &x, &y, &z });
        ccstAssertEqual((double)4, x.asDouble());
        ccstAssertEqual((double)5, z.asDouble())

        auto dx = JsonValue::number(4.3);
        auto dy = JsonValue::number(4.3);
        auto dz = JsonValue::number(5);
        ccstAssertEqual(dx, dy);
        ccstAssertNotEqual(dx, dz);
        ccstAssertNotEqual(dy, dz);
        testCasting(JsonValue::Double, { &dx, &dy, &dz });
        

        auto yes = JsonValue::yes();
        auto no  = JsonValue::no();
        auto bvalue = JsonValue(true);
        ccstAssertEqual(yes, bvalue);
        ccstAssertNotEqual(yes, no);
        ccstAssertNotEqual(no, bvalue);
        testCasting(JsonValue::Boolean, { &yes, &no, &bvalue });
        
        auto null1 = JsonValue(JsonValue::Null);
        auto null2 = JsonValue::null();
        ccstAssertEqual(null1, null2);
        testCasting(JsonValue::Null, { &null1, &null2 });
    }
    
    void testBytes()
    {
        auto d1 = JsonValue::string("SGVsbG8gV29ybGQ=");
        auto d2 = JsonValue::string("SGVsbG8gV29ybGQ");
        auto d3 = JsonValue::string("48656C6C6F20576F726C64");
        
        auto a1 = JsonValue::base64(cc7::MakeRange("Hello World"));
        auto a2 = JsonValue::base64Url(cc7::MakeRange("Hello World"));
        auto a3 = JsonValue::hexString(cc7::MakeRange("Hello World"));
        
        ccstAssertEqual(d1, a1);
        ccstAssertEqual(d2, a2);
        ccstAssertEqual(d3, a3);
        
        ccstAssertEqual(a1.asBase64(), cc7::MakeRange("Hello World"));
        ccstAssertEqual(a2.asBase64Url(), cc7::MakeRange("Hello World"));
        ccstAssertEqual(a3.asHexString(), cc7::MakeRange("Hello World"));
        
        testCasting(JsonValue::String, { &d1, &d2, &d3, &a1, &a2, &a3 });
    }
    
    void testMove()
    {
        // JsonValue move has a slightly different behavior now, because
        // internal `std::variant` keeps the type of value as is. So, it's
        // no longer defaulted to NaT as we did in original implementation.
        //
        // The analyzer may report a warning "Method called on moved-from object",
        // but that's the point of this test.
        
        auto val1 = JsonValue({ JsonValue("Hello"), JsonValue("World")});
        auto val2 = std::move(val1);
        
        ccstAssertTrue(val1.isType(JsonValue::Array));
        ccstAssertTrue(val2.isType(JsonValue::Array));
        ccstAssertEqual(0, val1.asArray().size());  // array in source object should be zeroed
        ccstAssertEqual(2, val2.asArray().size());
        
        ccstAssertEqual(val2, JsonValue({ JsonValue("Hello"), JsonValue("World")}));
    }
    
    void testCasting(JsonValue::Type expected_type, std::vector<JsonValue*> values)
    {
        for (auto & v : values) {
            auto& val = *v;
            auto type = val.type();
            ccstAssertEqual(expected_type, type);
            ccstAssertTrue(val.isType(expected_type));
            ccstAssertEqual(val, JsonValue(val));
            
            if (type == JsonValue::String) {
                val.asString();
            } else {
                ccstMustThrow(std::logic_error, val.asString());
                ccstMustThrow(std::logic_error, val.asBase64());
                ccstMustThrow(std::logic_error, val.asBase64Url());
                ccstMustThrow(std::logic_error, val.asHexString());
            }
            if (type == JsonValue::Object) {
                val.asObject();
            } else {
                ccstMustThrow(std::logic_error, val.asObject());
            }
            if (type == JsonValue::Array) {
                val.asArray();
            } else {
                ccstMustThrow(std::logic_error, val.asArray());
            }
            if (type == JsonValue::Integer) {
                val.asInteger();
            } else {
                ccstMustThrow(std::logic_error, val.asInteger());
            }
            if (type == JsonValue::Double) {
                val.asDouble();
            } else if (type == JsonValue::Integer) {
                // Casting from Integer to Double is allowed!!
                auto double_int = val.asDouble();
                ccstAssertEqual(double_int, (double)val.asInteger());
            } else {
                ccstMustThrow(std::logic_error, val.asDouble());
            }
            if (type == JsonValue::Boolean) {
                val.asBoolean();
            } else {
                ccstMustThrow(std::logic_error, val.asBoolean());
            }
            if (type == JsonValue::Null) {
                ccstAssertTrue(val.isNull());
            } else {
                ccstAssertFalse(val.isNull());
            }
            if (type == JsonValue::NaT) {
                ccstAssertFalse(val.isValid());
            } else {
                ccstAssertTrue(val.isValid());
            }
        }
    }
};

CC7_CREATE_UNIT_TEST(JsonValueTests, "cc7 test")

} // cc7::tests
} // cc7
