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
#include <jni.h>

namespace cc7::jni {

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
            /// constructor (String)
            JniMethod initMessage;
            /// constructor (String, Throwable)
            JniMethod initMessageCause;
        };
        static constexpr JniMethodSpec methodSpecs[3] = {
                { "<init>", "(V)V", offsetof(Methods, initMessage) },
                { "<init>", "(Ljava/lang/String;)V", offsetof(Methods, initMessage) },
                { "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", offsetof(Methods, initMessageCause) },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] = {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    /// Class specification for an object wrapping native handle. Object must implement constructor with
    /// (long handle) parameter and must contain "long handle" field.
    struct NativeHandleClass
    {
        // Methods
        struct Methods
        {
            // constructor (long handle)
            JniMethod initHandle;
        };
        // Method specs
        static constexpr JniMethodSpec methodSpecs[1] = {
                { "<init>", "(J)V", offsetof(Methods, initHandle) },
        };
        // Fields
        struct Fields
        {
            jfieldID handle;
        };

        // Field specs
        static constexpr JniFieldSpec fieldSpecs[] = {
                { "handle", "J", offsetof(Fields, handle) },
        };

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    // Common exceptions

    ExceptionSpec runtimeException;
    ExceptionSpec illegalStateException;
    ExceptionSpec illegalArgumentException;
};

} // namespace cc7::jni
