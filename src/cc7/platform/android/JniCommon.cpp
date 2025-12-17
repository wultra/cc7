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
        spec.specBoolean = jni.buildClassSpec<BooleanSpec>("java/lang/Boolean");
        spec.specLong = jni.buildClassSpec<LongSpec>("java/lang/Long");
        spec.specDouble = jni.buildClassSpec<DoubleSpec>("java/lang/Double");
        spec.specNumber = jni.buildClassSpec<NumberSpec>("java/lang/Number");
        spec.specList = jni.buildClassSpec<ListSpec>("java/util/List");
        spec.specArrayList = jni.buildClassSpec<ArrayListSpec>("java/util/ArrayList");
        spec.specMap = jni.buildClassSpec<MapSpec>("java/util/Map");
        spec.specMapEntry = jni.buildClassSpec<MapEntrySpec>("java/util/Map$Entry");
        spec.specHashMap = jni.buildClassSpec<HashMapSpec>("java/util/HashMap");
        spec.specSet = jni.buildClassSpec<SetSpec>("java/util/Set");
        spec.specIterator = jni.buildClassSpec<IteratorSpec>("java/util/Iterator");

        spec.classObject = jni.getClass("java/lang/Object").makeGlobal();
        spec.classString = jni.getClass("java/lang/String").makeGlobal();
        spec.classByte = jni.getClass("java/lang/Byte").makeGlobal();
        spec.classShort = jni.getClass("java/lang/Short").makeGlobal();
        spec.classInteger = jni.getClass("java/lang/Integer").makeGlobal();
        spec.classFloat = jni.getClass("java/lang/Float").makeGlobal();

        return spec;
    } catch (...) {
        // Cleanup
        jni.releaseSpec(spec.throwable);
        jni.releaseSpec(spec.runtimeException);
        jni.releaseSpec(spec.illegalStateException);
        jni.releaseSpec(spec.illegalArgumentException);
        jni.releaseSpec(spec.specBoolean);
        jni.releaseSpec(spec.specLong);
        jni.releaseSpec(spec.specDouble);
        jni.releaseSpec(spec.specNumber);
        jni.releaseSpec(spec.specList);
        jni.releaseSpec(spec.specArrayList);
        jni.releaseSpec(spec.specMap);
        jni.releaseSpec(spec.specMapEntry);
        jni.releaseSpec(spec.specHashMap);
        jni.releaseSpec(spec.specSet);
        jni.releaseSpec(spec.specIterator);
        jni.releaseObject(spec.classObject);
        jni.releaseObject(spec.classString);
        jni.releaseObject(spec.classByte);
        jni.releaseObject(spec.classShort);
        jni.releaseObject(spec.classInteger);
        jni.releaseObject(spec.classFloat);
        // Rethrow exception
        std::rethrow_exception(std::current_exception());
    }
}

} // namespace cc7::jni
