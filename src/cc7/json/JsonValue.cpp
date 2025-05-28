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

namespace cc7 {
namespace json {

// Operators

bool JsonValue::operator==(const JsonValue& other) const
{
    if (other.isType(_t)) {
        switch (_t) {
            case Array:
                return *_array == *other._array;
            case String:
                return *_string == *other._string;
            case Object:
                return *_object == *other._object;
            case Boolean:
                return _boolean == other._boolean;
            case Integer:
                return _integer == other._integer;
            case Double:
                return _double == other._double;
            case NaT:
            case Null:
                return true;
            default:
                break;
        }
    }
    return false;
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

void JsonValue::assignBase64(const cc7::ByteRange &data)
{
    assign(data.base64());
}

void JsonValue::assignBase64Url(const cc7::ByteRange &data)
{
    assign(data.base64Url());
}

void JsonValue::assignHexString(const cc7::ByteRange &data)
{
    assign(data.hexadecimal());
}

cc7::ByteArray JsonValue::dataFromBase64StringAtPath(const std::string & path) const
{
    return Base64::decode(stringAtPath(path));
}

cc7::ByteArray JsonValue::dataFromBase64UrlStringAtPath(const std::string & path) const
{
    return Base64::urlDecode(stringAtPath(path));
}

cc7::ByteArray JsonValue::dataFromHexStringAtPath(const std::string & path) const
{
    ByteArray result;
    if (!HexString_Decode(stringAtPath(path), result)) {
        throw std::invalid_argument("The selected string is not a hexadecimal string.");
    }
    return result;
}

// Utility

std::string JsonValue::typeToName(Type t)
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

} // namespace json
} // namespace cc7
