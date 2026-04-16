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

#include <cc7/json/JsonValue.h>
#include <cc7/Base64.h>
#include <cc7/HexString.h>
#include <cc7/detail/StringUtils.h>

namespace cc7::json {

// Constructor, Destructor, Copy, Move

JsonValue::JsonValue(Type t) noexcept
{
    switch (t) {
        case NaT:       _v = TNaT::Value; break;
        case Null:      _v = TNull::Value; break;
        case String:    _v = TString(); break;
        case Object:    _v = TObject(); break;
        case Array:     _v = TArray(); break;
        case Integer:   _v = 0; break;
        case Double:    _v = 0.0; break;
        case Boolean:   _v = false; break;
    }
}

JsonValue& JsonValue::operator=(const JsonValue& other)
{
    if (this != &other) {
        secureCleanup();
        _v = other._v;
    }
    return *this;
}

JsonValue& JsonValue::operator=(JsonValue&& other) noexcept
{
    if (this != &other) {
        secureCleanup();
        _v = std::move(other._v);
    }
    return *this;
}

JsonValue::~JsonValue()
{
    secureCleanup();
}

JsonValue::Type JsonValue::type() const noexcept
{
    auto index = _v.index();
    if (index != std::variant_npos) {
        return static_cast<Type>(index);
    }
    return NaT;
}

// Object access

JsonValue& JsonValue::operator[](const std::string& key)
{
    auto& obj = asMutableObject();
    auto it = obj.find(key);
    if (it != obj.end()) {
        return it->second;
    }
    obj[key] = JsonValue();
    return obj.find(key)->second;
}

const JsonValue& JsonValue::operator[](const std::string& key) const
{
    const auto& obj = asObject();
    auto it = obj.find(key);
    if (it != obj.end()) {
        return it->second;
    }
    throw std::invalid_argument("Key '" + key + "' doesn't exist");
}

JsonValue& JsonValue::operator[](size_t index)
{
    auto& arr = asMutableArray();
    if (index < arr.size()) {
        return arr[index];
    }
    throw std::invalid_argument("Index " + std::to_string(index) + " is out of range");
}

const JsonValue& JsonValue::operator[](size_t index) const
{
    const auto& arr = asArray();
    if (index < arr.size()) {
        return arr[index];
    }
    throw std::invalid_argument("Index " + std::to_string(index) + " is out of range");
}

const JsonValue * JsonValue::lookForValueAtPath(const std::string & path, Type expected_type, bool required) const
{
    auto path_components = detail::SplitString(path, '.');
    if (path_components.empty()) {
        if (required) throw std::invalid_argument("The provided path is wrong or empty.");
        return nullptr;
    }
    if (!isType(Object)) {
        if (required) throw std::invalid_argument("JsonValue is not an Object. Key: *this*");
        return nullptr;
    }
    const JsonValue * selected_obj = this;
    for (auto&& key : path_components) {
        if (selected_obj->isType(Object)) {
            auto&& object_map = selected_obj->asObject();
            auto value = object_map.find(key);
            if (value != object_map.end()) {
                selected_obj = &value->second;
            } else {
                if (required) throw std::invalid_argument("JsonValue at path not found. Path: '" + path + "', Missing key: '" + key + "'");
                return nullptr;
            }
        } else {
            if (required) throw std::invalid_argument("JsonValue is not an Object. Key: '" + key + "'");
            return nullptr;
        }
    }
    if (expected_type != NaT) {
        if (!selected_obj->isType(expected_type)) {
            if (required) throw std::invalid_argument("The selected JsonValue has unexpected type.");
            return nullptr;
        }
    }
    return selected_obj;
}

// ByteRange binding

void JsonValue::assignBase64(const ByteRange &data) noexcept
{
    assign(data.base64());
}

void JsonValue::assignBase64Url(const ByteRange &data) noexcept
{
    assign(data.base64Url());
}

void JsonValue::assignHexString(const ByteRange &data) noexcept
{
    assign(data.hexadecimal());
}

ByteArray JsonValue::dataFromBase64StringAtPath(const std::string & path) const
{
    return Base64::decode(stringAtPath(path));
}

ByteArray JsonValue::dataFromBase64UrlStringAtPath(const std::string & path) const
{
    return Base64::urlDecode(stringAtPath(path));
}

ByteArray JsonValue::dataFromHexStringAtPath(const std::string & path) const
{
    ByteArray result;
    if (!HexString_Decode(stringAtPath(path), result)) {
        throw std::invalid_argument("The selected string is not a hexadecimal string.");
    }
    return result;
}

ByteArray JsonValue::asBase64() const
{
    return Base64::decode(asString());
}

ByteArray JsonValue::asBase64Url() const
{
    return Base64::urlDecode(asString());
}

ByteArray JsonValue::asHexString() const
{
    return FromHexString(asString());
}

// Append / Insert

void JsonValue::reserve(size_t count)
{
    switch (type()) {
        case Array:
            asMutableArray().reserve(count);
            break;
        case String:
            asMutableString().reserve(count);
            break;
        default:
            break;
    }
}

void JsonValue::pushBack(const JsonValue &value)
{
    asMutableArray().push_back(value);
}

void JsonValue::pushBack(std::initializer_list<TArray::value_type> list)
{
    auto& array = asMutableArray();
    array.insert(array.end(), list);
}

void JsonValue::insert(const std::string& key, const JsonValue& value)
{
    asMutableObject()[key] = value;
}

void JsonValue::insert(std::initializer_list<TObject::value_type> list)
{
    asMutableObject().insert(list);
}

// Utility

void JsonValue::secureCleanup() noexcept
{
    if (type() == String) {
        // Cleanup string in destructor or in value assignment.
        detail::StringCleanup(std::get<TString>(_v));
    }
}

void JsonValue::castToType(Type t) const
{
    if (type() != t) {
        throw std::logic_error("Unable to cast JsonValue to " + std::string(typeToName(t)));
    }
}

const char * JsonValue::typeToName(Type t) noexcept
{
    switch (t) {
        case Null: return "Null";
        case Object: return "Object";
        case Array: return "Array";
        case String: return "String";
        case Integer: return "Integer";
        case Double: return "Double";
        case Boolean: return "Boolean";
        default: return "NaT";
    }
}

// Static constructors

JsonValue JsonValue::object() noexcept
{
    return JsonValue(Object);
}

JsonValue JsonValue::array() noexcept
{
    return JsonValue(Array);
}

JsonValue JsonValue::string() noexcept
{
    return JsonValue(String);
}

JsonValue JsonValue::object(std::initializer_list<TObject::value_type> list) noexcept
{
    return JsonValue(list);
}

JsonValue JsonValue::array(std::initializer_list<TArray::value_type> list) noexcept
{
    return JsonValue(list);
}

JsonValue JsonValue::string(const std::string_view& str) noexcept
{
    return JsonValue(str);
}

JsonValue JsonValue::string(const char* str) noexcept
{
    return JsonValue(str);
}

JsonValue JsonValue::string(const TString& str) noexcept
{
    return JsonValue(str);
}

JsonValue JsonValue::null() noexcept
{
    return JsonValue(Null);
}

JsonValue JsonValue::yes() noexcept
{
    return JsonValue(true);
}

JsonValue JsonValue::no() noexcept
{
    return JsonValue(false);
}

JsonValue JsonValue::boolean(bool value) noexcept
{
    return JsonValue(value);
}

JsonValue JsonValue::count(size_t c) noexcept
{
    return JsonValue((int64_t)c);
}

JsonValue JsonValue::integer(int64_t value) noexcept
{
    return JsonValue(value);
}

JsonValue JsonValue::number(double value) noexcept
{
    return JsonValue(value);
}

JsonValue JsonValue::base64(const ByteRange& data) noexcept
{
    return JsonValue(data.base64());
}

JsonValue JsonValue::base64Url(const ByteRange& data) noexcept
{
    return JsonValue(data.base64Url());
}

JsonValue JsonValue::hexString(const ByteRange& data) noexcept
{
    return JsonValue(data.hexadecimal());
}

} // namespace cc7::json
