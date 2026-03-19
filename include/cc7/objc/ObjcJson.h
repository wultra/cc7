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

#include <cc7/json/JsonValue.h>
#import <Foundation/Foundation.h>

namespace cc7::objc {

/// Function converts `JsonValue` into Objective-C JSON representation. The returned object
/// is `NSDictionary`, `NSArray`, `NSString`, `NSNumber` or `NSNull`, depending on type of
/// provided `JsonValue`.
///
/// - Parameters:
///   - value: Input `JsonValue` to convert
///   - null_is_nil: If `true`, then function returns `nil` if JsonValue is `Null` type, otherwise returns `NSNull` instance.
///                  This conversion is applied only to root object, provided in parameter. Any `Null` value deeper in object's hierarchy
///                  is converted to `NSNull`.
///   - nat_is_nil: If `true`, then function returns `nil` if JsonValue is `NaT` type (e.g. unassigned), otherwise exception is raised.
///                 This conversion is applied only to root object, provided in parameter. Any `NaT` value deeper in object's hierarchy
///                 cause an exception.
/// - Returns: Objective-C representation of given `JsonValue`.
/// - Throws:
///   - `std::invalid_argument` exception in case that value contains `NaT` type.
id JsonValueToObjC(const cc7::json::JsonValue& value, bool null_is_nil = true, bool nat_is_nil = true);

/// Function converts Objective-C JSON representation into `JsonValue`.
///
/// - Parameter json_representation: Objective-C representation of JSON.
/// - Returns: `JsonValue` created from given representation.
/// - Throws:
///   - `std::invalid_argument` exception in case that input object is unknown type.
cc7::json::JsonValue JsonValueFromObjC(id json_representation);

} // namespace cc7::objc
