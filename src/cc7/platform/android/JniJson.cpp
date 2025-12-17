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

#include <cc7/jni/JniJson.h>

using namespace cc7::json;

namespace cc7::jni {

// MARK: - JSON to Java

// Forward declarations
static jobject AnyToJava(JNI& jni, const JniCommon& specs, const JsonValue& value);

static jobject ObjectToJava(JNI& jni, const JniCommon& specs, const JsonValue::TObject& value)
{
    auto map = jni.createObject(specs.specHashMap.methods.initCapacity, (jint)value.size());
    for (auto& item : value) {
        // result from "put" should be always null (map is just created)
        map.callObject(specs.specMap.methods.put,
                       jni.toJava(item.first),
                       AnyToJava(jni, specs, item.second));
    }
    return map;
}

static jobject  ArrayToJava(JNI& jni, const JniCommon& specs, const JsonValue::TArray& value)
{
    auto array = jni.createObject(specs.specArrayList.methods.initCapacity, (jint)value.size());
    for (auto& item : value) {
        if (!array.callBoolean(specs.specList.methods.add, AnyToJava(jni, specs, item))) {
            throw JniException("Adding item to List<Object> failed");
        }
    }
    return array;
}

static jobject AnyToJava(JNI& jni, const JniCommon& specs, const JsonValue& value)
{
    switch (value.type()) {
        case JsonValue::Object:
            return ObjectToJava(jni, specs, value.asObject());

        case JsonValue::Array:
            return ArrayToJava(jni, specs, value.asArray());

        case JsonValue::String:
            return jni.toJava(value.asString());

        case JsonValue::Integer:
            return jni.createObject(specs.specLong.methods.initValue, (jlong) value.asInteger());

        case JsonValue::Double:
            return jni.createObject(specs.specDouble.methods.initValue, (jdouble) value.asDouble());

        case JsonValue::Boolean:
            return jni.createObject(specs.specBoolean.methods.initValue, (jboolean) value.asBoolean());

        case JsonValue::Null:
            return nullptr;

        default:
            throw std::invalid_argument("JsonValue contains NaT object");
    }
}

jobject JsonValueToJava(JNI& jni, const JsonValue& value, bool nat_is_null)
{
    switch (value.type()) {
        case JsonValue::Null:
            return nullptr;
        case JsonValue::NaT:
            if (nat_is_null) {
                return nullptr;
            }
            break;
        default:
            break;
    }
    return AnyToJava(jni, jni.commonSpecs(), value);
}


// MARK: - Java to JSON

// Forward declaration

static JsonValue AnyFromJava(JNI& jni, const JniCommon& specs, jobject obj);

static JsonValue ArrayFromJava(JNI& jni, const JniCommon& specs, jobject obj)
{
    auto result = JsonValue::array();
    auto wrapped = jni.fromJava(obj);
    auto size = wrapped.callInt(specs.specList.methods.size);
    for (size_t index = 0; index < size; size++) {
        auto item = jni.fromJava(wrapped.callObject(specs.specList.methods.get, (jint) index));
        result.pushBack(AnyFromJava(jni, specs, item));
        item.releaseLocal();
    }
    return result;
}

static JsonValue ObjectFromJava(JNI& jni, const JniCommon& specs, jobject obj)
{
    auto result = JsonValue::object();
    auto wrapped = jni.fromJava(obj);
    auto entry_set = jni.fromJava(wrapped.callObject(specs.specMap.methods.entrySet));
    auto iterator = jni.fromJava(entry_set.callObject(specs.specSet.methods.iterator));
    while (iterator.callBoolean(specs.specIterator.methods.hasNext)) {
        auto entry = jni.fromJava(iterator.callObject(specs.specIterator.methods.next));
        auto key = entry.callString(specs.specMapEntry.methods.getKey);
        auto value = entry.callObject(specs.specMapEntry.methods.getValue);
        result[key] = AnyFromJava(jni, specs, value);
        // cleanup
        entry.releaseLocal();
        value.releaseLocal();
    }
    // cleanup
    entry_set.releaseLocal();
    iterator.releaseLocal();
    return result;
}

static JsonValue AnyFromJava(JNI& jni, const JniCommon& specs, jobject obj)
{
    // "null"
    if (obj == nullptr) {
        return JsonValue::null();
    }
    // "String"
    if (jni.isInstanceOf(obj, specs.classString)) {
        return JsonValue(jni.fromJava((jstring)obj));
    }
    // [ items ]
    if (jni.isInstanceOf(obj, specs.specList.classRef)) {
        return ArrayFromJava(jni, specs, obj);
    }
    // { "key" : value }
    if (jni.isInstanceOf(obj, specs.specMap.classRef)) {
        return ObjectFromJava(jni, specs, obj);
    }
    // Integer
    if (jni.isInstanceOf(obj, specs.classInteger) || jni.isInstanceOf(obj, specs.specLong.classRef) ||
        jni.isInstanceOf(obj, specs.classShort) || jni.isInstanceOf(obj, specs.classByte)) {
        auto wrapped = jni.fromJava(obj, nullptr);
        auto value = wrapped.callLong(specs.specNumber.methods.longValue);
        return JsonValue::integer(value);
    }
    // Floating point numbers
    if (jni.isInstanceOf(obj, specs.classFloat) || jni.isInstanceOf(obj, specs.specDouble.classRef)) {
        auto wrapped = jni.fromJava(obj, nullptr);
        auto value = wrapped.callDouble(specs.specNumber.methods.doubleValue);
        return JsonValue::number(value);
    }
    // true | false
    if (jni.isInstanceOf(obj, specs.specBoolean.classRef)) {
        auto wrapped = jni.fromJava(obj, nullptr);
        auto value = wrapped.callBoolean(specs.specBoolean.methods.booleanValue);
        return JsonValue::boolean(value);
    }
    throw std::invalid_argument("Unsupported object type in Java JSON representation");
}

JsonValue JsonValueFromJava(JNI& jni, jobject obj)
{
    return AnyFromJava(jni, jni.commonSpecs(), obj);
}

} // namespace cc7::jni
