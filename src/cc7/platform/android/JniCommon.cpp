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

#include <cc7/jni/JniWrapper.h>

namespace cc7::jni {

JniCommon JniCommon::buildSpecs(JNI &jni)
{
    JniCommon spec {};
    try {
        spec.throwable = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/Throwable");
        spec.runtimeException = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/RuntimeException");
        spec.illegalStateException = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/IllegalStateException");
        spec.illegalArgumentException = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/IllegalArgumentException");
        spec.classString = jni.getClass("java/lang/String").makeGlobal();
        spec.classBoolean = jni.getClass("java/lang/Boolean").makeGlobal();
        spec.classDouble = jni.getClass("java/lang/Double").makeGlobal();
        spec.classLong = jni.getClass("java/lang/Long").makeGlobal();
        return spec;
    } catch (...) {
        // Cleanup
        jni.releaseSpec(spec.throwable);
        jni.releaseSpec(spec.runtimeException);
        jni.releaseSpec(spec.illegalStateException);
        jni.releaseSpec(spec.illegalArgumentException);
        jni.releaseObject(spec.classString);
        jni.releaseObject(spec.classBoolean);
        jni.releaseObject(spec.classDouble);
        jni.releaseObject(spec.classLong);
        // Rethrow exception
        std::rethrow_exception(std::current_exception());
    }
}

} // namespace cc7::jni
