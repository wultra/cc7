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

#include <cc7/Platform.h>
#include <unordered_set>
#include <jni.h>

namespace cc7::jni {

class JNI;

/// The `JniInitMethod` structure contains data for a Java object constructor.
struct JniInitMethod
{
    /// Method identifier.
    jmethodID methodId;
    /// Target class.
    jclass classRef;
};

/// The `JniMethod` represents method called on Java object. The method may be static, virtual or non-virtual.
typedef jmethodID JniMethod;

/// The `JniMethodType` enumeration defines method types for `JniMethodSpec` structure.
enum class JniMethodType
{
    Constructor,
    Method,
    NonVirtual,
    Static,
};

/// The `JniMethodSpec` contains method specification required for proper translation to method identifier.
struct JniMethodSpec
{
    /// Method's name.
    const char * name;
    /// Method's signature.
    const char * signature;
    /// Offset to T::Methods structure where the resolved method data will be stored.
    size_t targetOffset;
    /// Indicating that method is static.
    JniMethodType type;

    static constexpr JniMethodSpec constructor(const char * signature, size_t target_offset) {
        return { "<init>", signature, target_offset, JniMethodType::Constructor };
    }

    static constexpr JniMethodSpec method(const char * name, const char * signature, size_t target_offset) {
        return { name, signature, target_offset, JniMethodType::Method };
    }

    static constexpr JniMethodSpec nonVirtualMethod(const char * name, const char * signature, size_t target_offset) {
        return { name, signature, target_offset, JniMethodType::NonVirtual };
    }

    static constexpr JniMethodSpec staticMethod(const char * name, const char * signature, size_t target_offset) {
        return { name, signature, target_offset, JniMethodType::Static };
    }
};

enum class JniFieldType
{
    Field,
    Static
};

/// The `JniFieldSpec` contains field specification required for proper translation to field identifier.
struct JniFieldSpec
{
    /// Method's name.
    const char * name;
    /// Method's signature.
    const char * signature;
    /// Offset to T::Fields structure where the resolved field identifier will be stored.
    size_t targetOffset;
    /// Indicating that field is static
    JniFieldType type;

    static constexpr JniFieldSpec field(const char * name, const char * signature, size_t target_offset) {
        return { name, signature, target_offset, JniFieldType::Field };
    }

    static constexpr JniFieldSpec staticField(const char * name, const char * signature, size_t target_offset) {
        return { name, signature, target_offset, JniFieldType::Static };
    }
};

struct JniCommon
{
    /// Class specification for a generic exception.
    struct ExceptionSpec
    {
        struct Methods
        {
            /// constructor ()
            JniInitMethod init;
            /// constructor (String)
            JniInitMethod initMessage;
            /// constructor (String, Throwable)
            JniInitMethod initMessageCause;

            /// String getMessage();
            JniMethod getMessage;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("()V", offsetof(Methods, init)),
                JniMethodSpec::constructor("(Ljava/lang/String;)V", offsetof(Methods, initMessage)),
                JniMethodSpec::constructor("(Ljava/lang/String;Ljava/lang/Throwable;)V", offsetof(Methods, initMessageCause)),
                JniMethodSpec::method("getMessage", "()Ljava/lang/String;", offsetof(Methods, getMessage ))
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.lang.Boolean
    struct BooleanSpec
    {
        struct Methods
        {
            /// constructor (boolean value)
            JniInitMethod initValue;
            /// bool booleanValue()
            JniMethod booleanValue;
            /// Boolean::valueOf(boolean)
            JniMethod valueOf;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(Z)V", offsetof(Methods, initValue)),
                JniMethodSpec::method("booleanValue", "()Z", offsetof(Methods, booleanValue)),
                JniMethodSpec::staticMethod("valueOf", "(Z)Ljava/lang/Boolean;", offsetof(Methods, valueOf))
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.lang.Long
    struct LongSpec
    {
        struct Methods
        {
            /// constructor (long value)
            JniInitMethod initValue;
            /// Boolean::valueOf(boolean)
            JniMethod valueOf;
            /// long longValue()
            JniMethod longValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(J)V", offsetof(Methods, initValue)),
                JniMethodSpec::method("longValue", "()J", offsetof(Methods, longValue)),
                JniMethodSpec::staticMethod("valueOf", "(J)Ljava/lang/Long;", offsetof(Methods, valueOf))
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.lang.Double
    struct DoubleSpec
    {
        struct Methods
        {
            /// constructor (double value)
            JniInitMethod initValue;
            /// Boolean::valueOf(double)
            JniMethod valueOf;
            /// double doubleValue()
            JniMethod doubleValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(D)V", offsetof(Methods, initValue)),
                JniMethodSpec::method("doubleValue", "()D", offsetof(Methods, doubleValue)),
                JniMethodSpec::staticMethod("valueOf", "(D)Ljava/lang/Double;", offsetof(Methods, valueOf))
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.lang.Number
    struct NumberSpec
    {
        struct Methods
        {
            /// long longValue()
            JniMethod longValue;
            /// double doubleValue()
            JniMethod doubleValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::method("longValue", "()J", offsetof(Methods, longValue)),
                JniMethodSpec::method("doubleValue", "()D", offsetof(Methods, doubleValue)),
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.util.List
    struct ListSpec
    {
        struct Methods
        {
            JniMethod size;
            JniMethod get;
            JniMethod set;
            JniMethod add;
            JniMethod iterator;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::method("size", "()I", offsetof(Methods, size)),
                JniMethodSpec::method("get", "(I)Ljava/lang/Object;", offsetof(Methods, get)),
                JniMethodSpec::method("set", "(ILjava/lang/Object;)Ljava/lang/Object;", offsetof(Methods, set)),
                JniMethodSpec::method("add", "(Ljava/lang/Object;)Z", offsetof(Methods, add)),
                JniMethodSpec::method("iterator", "()Ljava/util/Iterator;", offsetof(Methods, iterator))
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.util.ArrayList
    struct ArrayListSpec
    {
        struct Methods
        {
            JniInitMethod initCapacity;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(I)V", offsetof(Methods, initCapacity))
        };
        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.util.Map
    struct MapSpec
    {
        struct Methods
        {
            JniMethod size;
            JniMethod get;
            JniMethod put;
            JniMethod entrySet;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::method("size", "()I", offsetof(Methods, size)),
                JniMethodSpec::method("get", "(Ljava/lang/Object;)Ljava/lang/Object;", offsetof(Methods, get)),
                JniMethodSpec::method("put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", offsetof(Methods, put)),
                JniMethodSpec::method("entrySet", "()Ljava/util/Set;", offsetof(Methods, entrySet)),
        };
        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.util.Map.Entry
    struct MapEntrySpec
    {
        struct Methods
        {
            JniMethod getKey;
            JniMethod getValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::method("getKey", "()Ljava/lang/Object;", offsetof(Methods, getKey)),
                JniMethodSpec::method("getValue", "()Ljava/lang/Object;", offsetof(Methods, getValue)),
        };
        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.util.HashMap
    struct HashMapSpec
    {
        struct Methods
        {
            JniInitMethod initCapacity;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(I)V", offsetof(Methods, initCapacity)),
        };
        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.util.Set
    struct SetSpec
    {
        struct Methods
        {
            JniMethod size;
            JniMethod iterator;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::method("size", "()I", offsetof(Methods, size)),
                JniMethodSpec::method("iterator", "()Ljava/util/Iterator;", offsetof(Methods, iterator)),
        };

        jclass classRef;
        Methods methods;
    };

    /// Class specification for java.lang.Iterator
    struct IteratorSpec
    {
        struct Methods
        {
            JniMethod hasNext;
            JniMethod next;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::method("hasNext", "()Z", offsetof(Methods, hasNext)),
                JniMethodSpec::method("next", "()Ljava/lang/Object;", offsetof(Methods, next)),
        };
        jclass classRef;
        Methods methods;
    };

    /// Structure describing Java class using native handle for wrapping C++ object.
    struct NativeHandleClass
    {
        jclass classRef;
        JniInitMethod initHandle;
        jfieldID handle;
        const char * className;
    };

    /// Specification for set of constants, such as `@interface IntEnums`
    struct ConstantSetSpec
    {
        jclass classRef;
        const char * className;
        std::unordered_set<jint> values;
    };

    /// Specification for range of constants, such as `@interface IntEnums`
    struct ConstantRangeSpec
    {
        jclass classRef;
        const char * className;
        jint bottomValue;
        jint topValue;
    };

    // Common exceptions

    ExceptionSpec throwable;
    ExceptionSpec runtimeException;
    ExceptionSpec illegalStateException;
    ExceptionSpec illegalArgumentException;

    // Common objects
    BooleanSpec specBoolean;
    LongSpec specLong;
    DoubleSpec specDouble;
    NumberSpec specNumber;
    ListSpec specList;
    ArrayListSpec specArrayList;
    MapSpec specMap;
    HashMapSpec specHashMap;
    MapEntrySpec specMapEntry;
    SetSpec specSet;
    IteratorSpec specIterator;

    jclass classObject;
    jclass classString;

    jclass classByte;
    jclass classShort;
    jclass classInteger;
    jclass classFloat;

    static JniCommon buildSpecs(JNI& jni);
};

} // namespace cc7::jni
