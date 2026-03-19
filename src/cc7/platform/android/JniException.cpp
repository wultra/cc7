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

#include <cc7/jni/JniException.h>
#include <cc7/jni/JniWrapper.h>

namespace cc7::jni {

const std::string JniException::CLASS_NAME = "cc7::jni::JniException";
const std::string JniBadHandleException::CLASS_NAME = "cc7::jni::JniBadHandleException";
const std::string JniJavaException::CLASS_NAME = "cc7::jni::JniJavaException";
const std::string JniFatalException::CLASS_NAME = "cc7::jni::JniFatalException";

// MARK: - JniJavaException

JniJavaException::JniJavaException(jthrowable throwable,
                                   const std::string& message,
                                   std::exception_ptr cause) :
        BaseException(message, cause),
        _throwable(throwable)
{
    if (!_throwable) {
        throw JniException("Missing throwable object in JniJavaException");
    }
}

} // namespace cc7::jni
