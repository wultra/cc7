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

namespace cc7 {
namespace objc {
    
static id JsonValueToObjCImpl(const JsonValue& value)
{
    switch (value.type()) {
        case JsonValue::Object: {
            NSMutableDictionary* out = [NSMutableDictionary dictionary];
            for (const auto& entry : value.asObject()) {
                NSString * key = [NSString stringWithUTF8String:entry.first.c_str()];
                NSString * value = JsonValueToObjCImpl(entry.second);
                [out setValue:value forKey:key];
            }
            return out;
        }
        case JsonValue::Array: {
            NSMutableArray* out = [NSMutableArray arrayWithCapacity:0];
            for (const auto& entry : value.asArray()) {
                [out addObject:JsonValueToObjCImpl(entry)];
            }
            return out;
        }
        case JsonValue::String:
            return [NSString stringWithUTF8String:value.asString().c_str()];
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
    return JsonValueToObjCImpl(value);
}

JsonValue JsonValueFromObjC(id repr)
{
    Class stringClass = [NSString class];
    if ([repr isKindOfClass:[NSDictionary class]]) {
        // convert NSDictionary<NSString*, id>
        auto __block object = JsonValue::object();
        [(NSDictionary*)repr enumerateKeysAndObjectsUsingBlock:^(id key, id  obj, BOOL * stop) {
            if (![key isKindOfClass:stringClass]) {
                throw std::invalid_argument("Unsupported key type in JSON representation");
            }
            auto c_key = std::string([((NSString*)key) UTF8String]);
            object[c_key] = JsonValueFromObjC(obj);
        }];
        return object;
        
    } else if ([repr isKindOfClass:[NSArray class]]) {
        // convert NSArray<id>
        auto __block array = JsonValue::array();
        [(NSArray*)repr enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
            array.pushBack(JsonValueFromObjC(obj));
        }];
        return array;
        
    } else if ([repr isKindOfClass:stringClass]) {
        // NSString
        return JsonValue::string(std::string([((NSString*)repr) UTF8String]));
        
    } else if ([repr isKindOfClass:[NSNumber class]]) {
        
        NSNumber* n = (NSNumber*)repr;
        switch (n.objCType[0]) {
            case 'c': {
                auto cv = n.charValue;
                if (cv == 0 || cv == 1) {
                    // @NO or @YES
                    return JsonValue::boolean(n.boolValue);
                }
                // fallback to integer
            }
            case 'i':
            case 's':
            case 'q':
                return JsonValue::integer(n.longLongValue);
            case 'f':
            case 'd':
                return JsonValue::number(n.doubleValue);
            default:
                throw std::invalid_argument("Unsupported type of NSNumber in JSON representation");
        }
    } else if ([repr isKindOfClass:[NSNull class]]) {
        return JsonValue::null();
    }
    throw std::invalid_argument("Unsupported object type in ObjC JSON representation");
}
    
} // namespace objc
} // namespace cc7
