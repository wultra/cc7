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

#pragma once

#include <cc7/ByteArray.h>
#include <cc7/Base64.h>
#include <map>
#include <vector>
#include <variant>

namespace cc7::json {

class JsonValue
{
public:
    
    enum Type
    {
        // not a type
        NaT,
        Null,
        Object,
        Array,
        String,
        Integer,
        Double,
        Boolean,
    };
        
    typedef std::map<std::string, JsonValue> TObject;
    typedef std::vector<JsonValue> TArray;
    typedef std::string TString;
        
    JsonValue()                             : _v(TNaT::Value) {}
    JsonValue(Type t);
    ~JsonValue();
    
    JsonValue(const JsonValue&) = default;
    JsonValue& operator=(const JsonValue&) = default;
    
    JsonValue(JsonValue&&) noexcept = default;
    JsonValue& operator=(JsonValue&&) noexcept = default;
    
    explicit JsonValue(std::initializer_list<TObject::value_type> list) : _v(TObject(list)) {}
    explicit JsonValue(std::initializer_list<TArray::value_type> list)  : _v(TArray(list)) {}
    
    explicit JsonValue(bool v)              : _v(v) {}
    explicit JsonValue(int64_t v)           : _v(v) {}
    explicit JsonValue(double v)            : _v(v) {}
    explicit JsonValue(const char* v)       : _v(v) {}
    explicit JsonValue(const TString& v)    : _v(v) {}
    explicit JsonValue(const std::string_view& v) : _v(TString(v)) {}
    explicit JsonValue(const TArray& v)     : _v(v) {}
    explicit JsonValue(const TObject& v)    : _v(v) {}
    
    // operators
    
    bool operator==(const JsonValue& other) const
    {
        return _v == other._v;
    }
    
    bool operator!=(const JsonValue& other) const
    {
        return _v != other._v;
    }
    
    // Object access
    JsonValue& operator[](const std::string& key);
    const JsonValue& operator[](const std::string& key) const;
    
    // Array access
    JsonValue& operator[](size_t index);
    const JsonValue& operator[](size_t index) const;
    
    
    // assign
    
    void assign(bool value)
    {
        _v = value;
    }
    
    void assign(int64_t value)
    {
        _v = value;
    }
    
    void assign(double value)
    {
        _v = value;
    }
    
    void assign(const TString & value)
    {
        _v = value;
    }
    
    void assign(const TObject & value)
    {
        _v = value;
    }
    
    void assign(const TArray & value)
    {
        _v = value;
    }
    
    void assignNull()
    {
        _v = TNull::Value;
    }
    
    // Append / Insert
    
    void reserve(size_t count);
    void pushBack(const JsonValue& value);
    void pushBack(std::initializer_list<TArray::value_type> list);
    void insert(const std::string& key, const JsonValue& value);
    void insert(std::initializer_list<TObject::value_type> list);
    
    // casting
    
    Type type() const
    {
        return static_cast<Type>(_v.index());
    }
    
    const TObject & asObject() const
    {
        castToType(Object);
        return std::get<TObject>(_v);
    }
    
    TObject & asMutableObject()
    {
        castToType(Object);
        return std::get<TObject>(_v);
    }
    
    const TArray & asArray() const
    {
        castToType(Array);
        return std::get<TArray>(_v);
    }
    
    TArray & asMutableArray()
    {
        castToType(Array);
        return std::get<TArray>(_v);
    }
    
    const TString & asString() const
    {
        castToType(String);
        return std::get<TString>(_v);
    }
    
    TString & asMutableString()
    {
        castToType(String);
        return std::get<TString>(_v);
    }
    
    double asDouble() const
    {
        if (type() == Integer) {
            // Auto-cast from integer to double
            return std::get<int64_t>(_v);
        }
        castToType(Double);
        return std::get<double>(_v);
    }
    
    int64_t asInteger() const
    {
        castToType(Integer);
        return std::get<int64_t>(_v);
    }
    
    bool asBoolean() const
    {
        castToType(Boolean);
        return std::get<bool>(_v);
    }
    
    ByteArray asBase64() const;
    ByteArray asBase64Url() const;
    ByteArray asHexString() const;
        
    bool isNull() const noexcept
    {
        return type() == Null;
    }
    
    bool isValid() const noexcept
    {
        return type() != NaT;
    }
    
    bool isType(Type t) const noexcept
    {
        return type() == t;
    }
    
    bool containsValueAtPath(const std::string & path, Type expected_type = NaT) const
    {
        return lookForValueAtPath(path, expected_type, false) != nullptr;
    }
    
    const JsonValue * findValueAtPath(const std::string & path, Type expected_type = NaT) const
    {
        return lookForValueAtPath(path, expected_type, false);
    }
    
    const JsonValue & valueAtPath(const std::string & path, Type expected_type = NaT) const
    {
        return *lookForValueAtPath(path, expected_type, true);
    }
    
    const JsonValue::TObject & objectAtPath(const std::string & path) const
    {
        return lookForValueAtPath(path, Object, true)->asObject();
    }
    
    const JsonValue::TArray & arrayAtPath(const std::string & path) const
    {
        return lookForValueAtPath(path, Array, true)->asArray();
    }
    
    const JsonValue::TString & stringAtPath(const std::string & path) const
    {
        return lookForValueAtPath(path, String, true)->asString();
    }
    
    const bool booleanAtPath(const std::string & path) const
    {
        return lookForValueAtPath(path, Boolean, true)->asBoolean();
    }
    
    const int64_t integerAtPath(const std::string & path) const
    {
        return lookForValueAtPath(path, Integer, true)->asInteger();
    }
    
    const double doubleAtPath(const std::string & path) const
    {
        return lookForValueAtPath(path, Double, true)->asDouble();
    }
    
    // byte array
    
    cc7::ByteArray dataFromBase64StringAtPath(const std::string & path) const;
    cc7::ByteArray dataFromBase64UrlStringAtPath(const std::string & path) const;
    cc7::ByteArray dataFromHexStringAtPath(const std::string & path) const;
    
    void assignBase64(const cc7::ByteRange & data);
    void assignBase64Url(const cc7::ByteRange & data);
    void assignHexString(const cc7::ByteRange & data);
    
    // Static constructs

    static JsonValue null();
    static JsonValue yes();
    static JsonValue no();
    static JsonValue object();
    static JsonValue array();
    static JsonValue string();
    static JsonValue object(std::initializer_list<TObject::value_type> list);
    static JsonValue array(std::initializer_list<TArray::value_type> list);
    static JsonValue string(const std::string_view& str);
    
    static JsonValue boolean(bool value);
    static JsonValue count(size_t c);
    static JsonValue integer(int64_t value);
    static JsonValue number(double value);

    static JsonValue base64(const ByteRange& data);
    static JsonValue base64Url(const ByteRange& data);
    static JsonValue hexString(const ByteRange& data);
    
    
    // Debug
    
    void debugDump() const;
    
private:
    
    enum class TNaT  { Value };
    enum class TNull { Value };

    // Be aware that order of the types in variant must match order
    // in enum Type. If not, then type() function will not work properly.
    
    typedef std::variant
    <
        TNaT,
        TNull,
        TObject,
        TArray,
        TString,
        int64_t,
        double,
        bool
    > Value;

    Value _v;
    
    // Private methods
    
    const JsonValue * lookForValueAtPath(const std::string & path, Type expected_type, bool required) const;
        
    void castToType(Type t) const
    {
        if (type() != t) {
            throw std::logic_error("Unable to cast JsonValue to " + typeToName(t));
        }
    }
        
    static std::string typeToName(Type t);
};

} // namespace cc7::json
