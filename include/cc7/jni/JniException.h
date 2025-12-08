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

#include <cc7/BaseException.h>
#include <jni.h>

namespace cc7::jni {

/// The `JniException` is raised in case the unexpected error occurred. This type of exception is
/// typically converted into `IllegalStateException` and reported back to Java.
class JniException : public BaseException
{
public:
    using BaseException::BaseException;
    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }
private:
    static const std::string CLASS_NAME;
};

/// The `JniBadHandleException` is raised in case the provided handle is no longer in object register.
/// This type of exception is typically converted into `IllegalStateException` and reported back to Java.
class JniBadHandleException : public JniException
{
public:
    using JniException::JniException;
    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }
private:
    static const std::string CLASS_NAME;
};

/// The `JniJavaException` wraps Java Throwable object and is typically reported after a failed
/// JNI call. The wrapped Throwable is then reported back to Java.
class JniJavaException : public BaseException
{
public:
    using BaseException::BaseException;

    JniJavaException(jthrowable throwable,
                     const std::string& message,
                     std::exception_ptr cause = std::current_exception());

    jthrowable throwable() const { return _throwable; }

    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }

private:
    jthrowable _throwable;
    static const std::string CLASS_NAME;
};

/// The `JniFatalException` is raised when an unrecoverable error is reported. The exception
/// is then typically converted into a JNI fatal failure.
class JniFatalException : public BaseException
{
public:
    using BaseException::BaseException;
    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }
private:
    static const std::string CLASS_NAME;
};

} // namespace cc7::jni
