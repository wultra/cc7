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

/// The `JniMethod` structure contains data for a Java method execution.
struct JniMethod
{
    /// Target class.
    jclass classRef;
    /// Method identifier.
    jmethodID methodId;
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
    bool isStatic;
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
    bool isStatic;
};

struct JniCommon
{
    /// Class specification for a generic exception.
    struct ExceptionSpec
    {
        struct Methods
        {
            /// constructor ()
            JniMethod init;
            /// constructor (String)
            JniMethod initMessage;
            /// constructor (String, Throwable)
            JniMethod initMessageCause;
            /// String getMessage();
            JniMethod getMessage;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "<init>", "()V", offsetof(Methods, init) },
            { "<init>", "(Ljava/lang/String;)V", offsetof(Methods, initMessage) },
            { "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", offsetof(Methods, initMessageCause) },
            { "getMessage", "()Ljava/lang/String;", offsetof(Methods, getMessage ) },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Class specification for java.lang.Boolean
    struct BooleanSpec
    {
        struct Methods
        {
            /// constructor (boolean value)
            JniMethod initValue;
            /// Boolean::valueOf(boolean)
            JniMethod valueOf;
            /// bool booleanValue()
            JniMethod booleanValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "<init>", "(Z)V", offsetof(Methods, initValue) },
            { "booleanValue", "()Z", offsetof(Methods, booleanValue) },
            { "valueOf", "(Z)Ljava/lang/Boolean;", offsetof(Methods, valueOf), true },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Class specification for java.lang.Long
    struct LongSpec
    {
        struct Methods
        {
            /// constructor (long value)
            JniMethod initValue;
            /// Boolean::valueOf(boolean)
            JniMethod valueOf;
            /// long longValue()
            JniMethod longValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "<init>", "(J)V", offsetof(Methods, initValue) },
            { "longValue", "()J", offsetof(Methods, longValue) },
            { "valueOf", "(J)Ljava/lang/Long;", offsetof(Methods, valueOf), true },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Class specification for java.lang.Double
    struct DoubleSpec
    {
        struct Methods
        {
            /// constructor (double value)
            JniMethod initValue;
            /// Boolean::valueOf(double)
            JniMethod valueOf;
            /// double doubleValue()
            JniMethod doubleValue;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "<init>", "(D)V", offsetof(Methods, initValue) },
            { "doubleValue", "()D", offsetof(Methods, doubleValue) },
            { "valueOf", "(D)Ljava/lang/Double;", offsetof(Methods, valueOf), true },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
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
            { "longValue", "()J", offsetof(Methods, longValue) },
            { "doubleValue", "()D", offsetof(Methods, doubleValue) },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
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
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "size", "()I", offsetof(Methods, size) },
            { "get", "(I)Ljava/lang/Object;", offsetof(Methods, get) },
            { "set", "(ILjava/lang/Object;)Ljava/lang/Object;", offsetof(Methods, set) },
            {"add", "(Ljava/lang/Object;)Z", offsetof(Methods, add) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Class specification for java.util.ArrayList
    struct ArrayListSpec
    {
        struct Methods
        {
            JniMethod initCapacity;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "<init>", "(I)V", offsetof(Methods, initCapacity) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
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
            { "size", "()I", offsetof(Methods, size) },
            { "get", "(Ljava/lang/Object;)Ljava/lang/Object;", offsetof(Methods, get) },
            { "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", offsetof(Methods, put) },
            { "entrySet", "()Ljava/util/Set;", offsetof(Methods, entrySet) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
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
                { "getKey", "()Ljava/lang/Object;", offsetof(Methods, getKey) },
                { "getValue", "()Ljava/lang/Object;", offsetof(Methods, getValue) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Class specification for java.util.HashMap
    struct HashMapSpec
    {
        struct Methods
        {
            JniMethod initCapacity;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
            { "<init>", "(I)V", offsetof(Methods, initCapacity) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
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
                { "size", "()I", offsetof(Methods, size) },
                { "iterator", "()Ljava/util/Iterator;", offsetof(Methods, iterator) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
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
                { "hasNext", "()Z", offsetof(Methods, hasNext) },
                { "next", "()Ljava/lang/Object;", offsetof(Methods, next) },
        };
        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Structure describing Java class using native handle for wrapping C++ object.
    struct NativeHandleClass
    {
        jclass classRef;
        JniMethod initHandle;
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
