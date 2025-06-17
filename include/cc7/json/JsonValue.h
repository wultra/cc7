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
#include <cc7/detail/StringUtils.h>
#include <map>
#include <vector>

namespace cc7 {
namespace json {

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
    
    JsonValue()                     : _t(NaT), _copy_ptr(nullptr) {}
    
    JsonValue(Type t)               : _t(t), _copy_ptr(nullptr)
    {
        switch (_t) {
            case String: _string = new TString(); break;
            case Object: _object = new TObject(); break;
            case Array:  _array  = new TArray();  break;
            default:
                break;
        }
    }
    
    explicit JsonValue(std::initializer_list<TObject::value_type> list) : _t(Object), _object(new TObject(list)) {}
    explicit JsonValue(std::initializer_list<TArray::value_type> list)  : _t(Array),  _array(new TArray(list)) {}
    
    explicit JsonValue(bool v)      : _t(Boolean), _boolean(v) {}
    explicit JsonValue(int64_t v)   : _t(Integer), _integer(v) {}
    explicit JsonValue(double v)    : _t(Double),  _double(v) {}
    explicit JsonValue(const char* v) : _t(String)
    {
        _string = new TString(v);
    }
    explicit JsonValue(const TString& v) : _t(String)
    {
        _string = new TString(v);
    }
    explicit JsonValue(const std::string_view& v) : _t(String)
    {
        _string = new TString(v);
    }
    explicit JsonValue(const TArray& v) : _t(Array)
    {
        _array = new TArray(v);
    }
    explicit JsonValue(const TObject& v) : _t(Object)
    {
        _object = new TObject(v);
    }
    
    // Copy / Move
    
    JsonValue(const JsonValue & o)
    {
        copyFrom(o);
    }
    
    JsonValue(JsonValue && o) : _t(o._t), _copy_ptr(o._copy_ptr)
    {
        o._t = NaT;
    }
    
    JsonValue & operator=(const JsonValue & o)
    {
        if (&o != this) {
            destroy();
            copyFrom(o);
        }
        return *this;
    }
    
    JsonValue & operator=(JsonValue && o)
    {
        _t = o._t;
        _copy_ptr = o._copy_ptr;
        o._t = NaT;
        return *this;
    }
    
    // Destructor
    
    ~JsonValue()
    {
        destroy();
    }
    
    // operators
    
    bool operator==(const JsonValue& other) const;
    bool operator!=(const JsonValue& other) const
    {
        return !this->operator==(other);
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
        destroy();
        _t = Boolean;
        _boolean = value;
    }
    
    void assign(int64_t value)
    {
        destroy();
        _t = Integer;
        _integer = value;
    }
    
    void assign(double value)
    {
        destroy();
        _t = Double;
        _double = value;
    }
    
    void assign(const TString & value)
    {
        destroy();
        _t = String;
        _string = new TString(value);
    }
    
    void assign(const TObject & value)
    {
        destroy();
        _t = Object;
        _object = new TObject(value);
    }
    
    void assign(const TArray & value)
    {
        destroy();
        _t = Array;
        _array = new TArray(value);
    }
    
    void assignNull()
    {
        destroy();
        _t = Null;
    }
    
    // Append
    
    void pushBack(const JsonValue& value)
    {
        asMutableArray().push_back(value);
    }
    
    // casting
    
    Type type() const
    {
        return _t;
    }
    
    const TObject & asObject() const
    {
        castToPtrType(Object);
        return *_object;
    }
    
    TObject & asMutableObject()
    {
        castToPtrType(Object);
        return *_object;
    }
    
    const TArray & asArray() const
    {
        castToPtrType(Array);
        return *_array;
    }
    
    TArray & asMutableArray()
    {
        castToPtrType(Array);
        return *_array;
    }
    
    const TString & asString() const
    {
        castToPtrType(String);
        return *_string;
    }
    
    TString & asMutableString()
    {
        castToPtrType(String);
        return *_string;
    }
    
    double asDouble() const
    {
        if (_t == Integer) {
            // Auto-cast from integer to double
            return static_cast<double>(_integer);
        }
        castToType(Double);
        return _double;
    }
    
    int64_t asInteger() const
    {
        castToType(Integer);
        return _integer;
    }
    
    bool asBoolean() const
    {
        castToType(Boolean);
        return _boolean;
    }
    
    ByteArray asBase64() const;
    ByteArray asBase64Url() const;
    ByteArray asHexString() const;
        
    bool isNull() const noexcept
    {
        return _t == Null;
    }
    
    bool isValid() const noexcept
    {
        return _t != NaT;
    }
    
    bool isType(Type t) const noexcept
    {
        return _t == t;
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
    
    static JsonValue count(size_t c);
    static JsonValue integer(int64_t value);
    static JsonValue number(double value);

    static JsonValue base64(const ByteRange& data);
    static JsonValue base64Url(const ByteRange& data);
    static JsonValue hexString(const ByteRange& data);
    
    
    // Debug
    
    void debugDump() const;
    
private:
    
    // Private members
    
    Type _t;
    union
    {
        bool        _boolean;
        int64_t     _integer;
        double      _double;
        TObject *   _object;
        TArray *    _array;
        TString *   _string;
        void *      _copy_ptr;
    };
    
    // Private methods
    
    const JsonValue * lookForValueAtPath(const std::string & path, Type expected_type, bool required) const;
    
    void destroy()
    {
        switch (_t) {
            case Object:
                delete _object;
                break;
            case Array:
                delete _array;
                break;
            case String:
                detail::StringCleanup(*_string);
                delete _string;
                break;
            default:
                break;
        }
        _integer = 0;
    }
    
    void copyFrom(const JsonValue & o)
    {
        _t = o._t;
        switch (o._t) {
            case String: _string = new TString(*o._string); break;
            case Object: _object = new TObject(*o._object); break;
            case Array:  _array  = new TArray(*o._array);   break;
            default:
                _copy_ptr = o._copy_ptr;
                break;
        }
    }
    
    void castToType(Type t) const
    {
        if (_t != t) {
            throw std::logic_error("Unable to cast JsonValue to " + typeToName(t));
        }
    }
    
    void castToPtrType(Type t) const
    {
        castToType(t);
        if (_object == nullptr) {
            throw std::logic_error("JsonValue with type " + typeToName(t) + " has no ");
        }
    }
    
    static std::string typeToName(Type t);
};

} // namespace json
} // namespace cc7
