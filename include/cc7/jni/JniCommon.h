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
        static constexpr JniMethodSpec methodSpecs[4] = {
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

    jclass classString;
    jclass classBoolean;
    jclass classDouble;
    jclass classLong;

    static JniCommon buildSpecs(JNI& jni);
};

} // namespace cc7::jni
