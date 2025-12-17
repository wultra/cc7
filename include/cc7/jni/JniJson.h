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

#include <cc7/jni/JniWrapper.h>
#include <cc7/json/Json.h>

namespace cc7::jni {

/// Convert JsonValue into hierarchy of java objects, with the following type mapping:
/// - string value is mapped to String
/// - double value is mapped to Double
/// - long value is mapped to Long
/// - bool value is mapped to Boolean
/// - object value is mapped to Map<String, Object>
/// - array value is mapped to List<Object>
/// - null is mapped to null
/// @param jni JNI reference.
/// @param obj JSON object to convert.
/// @param nat_is_null If true, then NaT is treated as null, otherwise exception is reported. This conversion
///        is applied only to root object, provided in parameter. Any `NaT` value deeper in object's hierarchy
///        cause an exception.
/// @return Java object converted from JSON representation.
jobject JsonValueToJava(JNI& jni, const cc7::json::JsonValue& obj, bool nat_is_null = true);

/// Convert java object into JSON representation, with the following type mapping:
/// - String object is mapped to string value.
/// - Double or Float objects are mapped to double value.
/// - Long, Integer, Short or Byte objects are mapped to integer value.
/// - Boolean object is mapped to bool value.
/// - Map<String, Object> object is mapped to object value.
/// - List<Object> is mapped to array value.
/// - null is mapped to null
/// @param jni JNI reference.
/// @param obj Object to convert.
/// @return JSON representation.
cc7::json::JsonValue JsonValueFromJava(JNI& jni, jobject obj);

} // namespace cc7::jni
