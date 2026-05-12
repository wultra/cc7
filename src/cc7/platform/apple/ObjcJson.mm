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

#include <cc7/objc/ObjcJson.h>

using namespace cc7::json;

namespace cc7::objc {

static const int MAX_DEPTH = 32;

static id JsonValueToObjCImpl(const JsonValue& value, int depth)
{
    if (depth > MAX_DEPTH) {
        throw std::invalid_argument("JsonValue is too complex to convert");
    }
    switch (value.type()) {
        case JsonValue::Object: {
            NSMutableDictionary* out = [NSMutableDictionary dictionary];
            for (const auto& entry : value.asObject()) {
                NSString * key = [NSString stringWithUTF8String:entry.first.c_str()];
                if (!key) {
                    throw std::invalid_argument("JsonValue contains invalid string");
                }
                id value = JsonValueToObjCImpl(entry.second, depth + 1);
                if (!value) {
                    throw std::invalid_argument("JsonValue failed to convert to ObjC representation");
                }
                [out setValue:value forKey:key];
            }
            return out;
        }
        case JsonValue::Array: {
            NSMutableArray* out = [NSMutableArray arrayWithCapacity:0];
            for (const auto& entry : value.asArray()) {
                [out addObject:JsonValueToObjCImpl(entry, depth + 1)];
            }
            return out;
        }
        case JsonValue::String: {
            NSString * string = [NSString stringWithUTF8String:value.asString().c_str()];
            if (!string) {
                throw std::invalid_argument("JsonValue contains invalid string");
            }
            return string;
        }
        case JsonValue::Integer:
            return [NSNumber numberWithInteger:value.asInteger()];
        case JsonValue::Double:
            return [NSNumber numberWithDouble:value.asDouble()];
        case JsonValue::Boolean:
            return [NSNumber numberWithBool:value.asBoolean()];
        case JsonValue::Null:
            return [NSNull null];
        default:
            throw std::invalid_argument("JsonValue contains NaT object");
    }
}

id JsonValueToObjC(const cc7::json::JsonValue& value, bool null_is_nil, bool nat_is_nil)
{
    switch (value.type()) {
        case JsonValue::Null:
            return null_is_nil ? nil : [NSNull null];
        case JsonValue::NaT:
            if (nat_is_nil) {
                return nil;
            }
            break;
        default:
            break;
    }
    return JsonValueToObjCImpl(value, 0);
}

static JsonValue JsonValueFromObjCImpl(id repr, int depth)
{
    if (depth > MAX_DEPTH) {
        throw std::invalid_argument("JSON representation is too complex to convert");
    }
    Class stringClass = [NSString class];
    if ([repr isKindOfClass:[NSDictionary class]]) {
        // convert NSDictionary<NSString*, id>
        auto __block object = JsonValue::object();
        [(NSDictionary*)repr enumerateKeysAndObjectsUsingBlock:^(id key, id  obj, BOOL * stop) {
            if (![key isKindOfClass:stringClass]) {
                throw std::invalid_argument("Unsupported key type in JSON representation");
            }
            auto key_str = [((NSString*)key) UTF8String];
            if (!key_str) {
                throw std::invalid_argument("Key contains invalid UTF-8 sequence in JSON representation");
            }
            object[std::string(key_str)] = JsonValueFromObjCImpl(obj, depth + 1);
        }];
        return object;
        
    } else if ([repr isKindOfClass:[NSArray class]]) {
        // convert NSArray<id>
        auto __block array = JsonValue::array();
        [(NSArray*)repr enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
            array.pushBack(JsonValueFromObjCImpl(obj, depth + 1));
        }];
        return array;
        
    } else if ([repr isKindOfClass:stringClass]) {
        // NSString
        auto str = [((NSString*)repr) UTF8String];
        if (!str) {
            throw std::invalid_argument("String contains invalid UTF-8 sequence in JSON representation");
        }
        return JsonValue::string(std::string(str));
        
    } else if ([repr isKindOfClass:[NSNumber class]]) {
        
        NSNumber* n = (NSNumber*)repr;
        switch (n.objCType[0]) {
            case 'C':   // unsigned char
            case 'c': { // char
                auto cv = n.charValue;
                if (cv == 0 || cv == 1) {
                    // @NO or @YES
                    return JsonValue::boolean(n.boolValue);
                }
                // fallback to integer
            }
            case 'Q':   // unsigned long long
            case 'q':   // long long
            case 'L':   // unsigned long
            case 'l':   // long
            case 'I':   // unsigned int
            case 'i':   // int
            case 'S':   // unsigned short
            case 's':   // short
                return JsonValue::integer(n.longLongValue);
            case 'f':
            case 'd':
                return JsonValue::number(n.doubleValue);
            case 'B':
                return JsonValue::boolean(n.boolValue);
            default:
                throw std::invalid_argument("Unsupported type of NSNumber in JSON representation");
        }
    } else if ([repr isKindOfClass:[NSNull class]]) {
        return JsonValue::null();
    }
    throw std::invalid_argument("Unsupported object type in ObjC JSON representation");
}

JsonValue JsonValueFromObjC(id repr)
{
    return JsonValueFromObjCImpl(repr, 0);
}
    
} // namespace cc7::objc
