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

// MARK: - JNIGlobal

std::once_flag JNIGlobal::s_init_flag;
JNIGlobal * JNIGlobal::s_instance = nullptr;

static std::vector<JNIGlobal::GlobalInitializer>& initializers()
{
    static std::vector<JNIGlobal::GlobalInitializer> initializers;
    return initializers;
}

static std::mutex& initializers_mutex()
{
    static std::mutex mutex;
    return mutex;
}

JNIGlobal& JNIGlobal::global(JNIEnv * env)
{
    std::call_once(s_init_flag, [env] {
        try {
            // Create temporary JNI object that doesn't handle exceptions.
            // If exception occurs during the code execution, then FatalError() is raised.
            JNI temporary(env, nullptr, 0);

            // Create JNIGlobal instance
            s_instance = new JNIGlobal(temporary);

            // Get and call all global initializers
            std::vector<GlobalInitializer> init_functions;
            {
                std::lock_guard<std::mutex> lock(initializers_mutex());
                init_functions = initializers();
                // Cleanup initializer functions
                initializers().clear();
            }
            for (auto &func: init_functions) {
                func(temporary);
            }
        } catch (BaseException & e) {
            env->FatalError(("JNIGlobal initialization sequence failed: " + e.message()).c_str());
        } catch (std::exception & e) {
            env->FatalError((std::string("JNIGlobal initialization sequence failed: ") + e.what()).c_str());
        } catch (...) {
            env->FatalError("JNIGlobal initialization sequence failed with unsupported exception");
        }
    });
    return *s_instance;
}

JNI JNIGlobal::local(JNIEnv *env, jint local_ref_capacity)
{
    return { env, &global(env), local_ref_capacity };
}

void JNIGlobal::addGlobalInitializer(const GlobalInitializer& initializer)
{
    std::lock_guard<std::mutex> lock(initializers_mutex());
    initializers().push_back(initializer);
}

JNIGlobal::JNIGlobal(JNI &jni) :
    _specs(buildSpecs(jni))
{
}

JniCommon JNIGlobal::buildSpecs(JNI &jni)
{
    JniCommon spec {};
    try {
        spec.runtimeException = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/RuntimeException");
        spec.illegalStateException = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/IllegalStateException");
        spec.illegalArgumentException = jni.buildClassSpec<JniCommon::ExceptionSpec>("java/lang/IllegalArgumentException");
        return spec;
    } catch (...) {
        // Cleanup
        jni.releaseObject(spec.runtimeException.classRef);
        jni.releaseObject(spec.illegalStateException.classRef);
        jni.releaseObject(spec.illegalArgumentException.classRef);
        // Rethrow exception
        std::rethrow_exception(std::current_exception());
    }
}

// MARK: - JNI

// Instance management

JNI::JNI(JNIEnv *env, cc7::jni::JNIGlobal *global, jint local_ref_capacity) :
    _env(env),
    _global(global)
{
    if (local_ref_capacity) {
        // Reserve enough capacity in the current frame
        _env->EnsureLocalCapacity(local_ref_capacity);
        checkForJniFailure("EnsureLocalCapacity");
    }
}

JNIGlobal& JNI::global()
{
    if (!_global) {
        throw JniException("JNIGlobal register is not available");
    }
    return *_global;
}

JNIGlobal& JNI::globalOrFatal()
{
    if (!_global) {
        _env->FatalError("JNIGlobal instance is not set, exception processing is unavailable.");
    }
    return *_global;
}

// Parameters

void JNI::requireParameter(jobject object, const char *param_name)
{
    if (!object) {
        throw std::invalid_argument(std::string("Required parameter \"") + param_name + "\" is missing");
    }
}

// Bytes

ByteArray JNI::fromJava(jbyteArray array)
{
    ByteArray result;
    if (array) {
        auto length = _env->GetArrayLength(array);
        if (length > 0) {
            jboolean is_copy = false;
            auto bytes = _env->GetByteArrayElements(array, &is_copy);
            if (!bytes) {
                wrapCurrentThrowable("GetByteArrayElements");
            }
            result.assign(bytes, bytes + length);
            if (is_copy) {
                // If returned pointer is a copy, then cleanup bytes, to do not leak
                // possible sensitive information.
                memset(bytes, 0, length);
            }
            // release allocated bytes
            _env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
            checkForJniFailure("ReleaseByteArrayElements");
        }
    }
    return result;
}

ByteArray JNI::fromJavaStringToBytes(jstring string)
{
    ByteArray res;
    if (string) {
        auto str_ptr = _env->GetStringUTFChars(string, nullptr);
        if (!str_ptr) {
            wrapCurrentThrowable("GetStringUTFChars");
        }
        res.assign(MakeRange(str_ptr));
        _env->ReleaseStringUTFChars(string, str_ptr);
        checkForJniFailure("ReleaseStringUTFChars");
    }
    return res;
}

jbyteArray JNI::toJava(const ByteRange& range)
{
    auto array = _env->NewByteArray((jsize) range.size());
    if (!array) {
        wrapCurrentThrowable("NewByteArray");
    }
    _env->SetByteArrayRegion (array, 0, (jsize) range.size(), (const jbyte*)range.data());
    checkForJniFailure("SetByteArrayRegion");
    return array;
}

jbyteArray JNI::toJavaNullable(const ByteRange& range)
{
    if (range.empty()) {
        return nullptr;
    }
    return toJava(range);
}

// String

std::string JNI::fromJava(jstring string)
{
    std::string result;
    if (string) {
        auto str_ptr = _env->GetStringUTFChars(string, nullptr);
        if (!str_ptr) {
            wrapCurrentThrowable("GetStringUTFChars");
        }
        result.assign(str_ptr);
        _env->ReleaseStringUTFChars(string, str_ptr);
        checkForJniFailure("ReleaseStringUTFChars");
    }
    return result;
}

jstring JNI::toJava(const char* string)
{
    auto result = _env->NewStringUTF(string ? string : "");
    checkForJniFailure("NewStringUTF");
    return result;
}

jstring JNI::toJava(const std::string& string)
{
    auto result = _env->NewStringUTF(string.c_str());
    checkForJniFailure("NewStringUTF");
    return result;
}

jstring JNI::toJava(const std::string_view & string)
{
    return toJava(std::string(string));
}

jstring JNI::toJavaNullable(const std::string& string)
{
    if (string.empty()) {
        return nullptr;
    }
    return toJava(string);
}

jstring JNI::toJavaNullable(const std::string_view& string)
{
    return toJavaNullable(std::string(string));
}

// Arrays

JniObjectArray JNI::fromJava(jobjectArray array)
{
    jsize size;
    if (array) {
        size = _env->GetArrayLength(array);
        checkForJniFailure("GetArrayLength");
    } else {
        size = 0;
    }
    return { this, size, array };
}

// Objects

JniObject JNI::createObject(JniMethod constructor, ...)
{
    va_list args;
    va_start(args, constructor);
    auto result = _env->NewObjectV(constructor.classRef, constructor.methodId, args);
    va_end(args);
    checkForJniFailure("NewObjectV");
    return {this, result };
}

JniObject JNI::createObjectV(const JniMethod& constructor, va_list args)
{
    auto result = _env->NewObjectV(constructor.classRef, constructor.methodId, args);
    checkForJniFailure("NewObjectV");
    return {this, result };
}

JniObject JNI::fromJava(jobject object, jclass clazz)
{
    if (object && clazz) {
        // Both object and class is specified, check the type.
        if (!isExactObjectType(object, clazz)) {
            throw JniException("Different Java object type passed to native code");
        }
    }
    return { this, object };
}

// Handle based objects

jlong JNI::toHandle(const BaseObjectPtr& object, bool release_on_exception)
{
    auto handle = global().objectRegister().registerObject(object);
    if (release_on_exception) {
        _release_on_fail.push_back(handle);
    }
    return handle;
}

jobject JNI::toJava(const JniCommon::NativeHandleClass& spec, const BaseObjectPtr& object)
{
    auto& reg = global().objectRegister();
    auto handle = reg.registerObject(object);
    try {
        return createObject(spec.methods.initHandle, handle);
    } catch (...) {
        // Delete registered instance and re-throw exception.
        reg.removeObject(handle);
        std::rethrow_exception(std::current_exception());
    }
}

// Class management

jclass JNI::findClass(const char *class_name)
{
    if (!class_name) {
        throw JniException("Class name is null in findClass()");
    }
    auto clazz = _env->FindClass(class_name);
    checkForJniFailure("FindClass");
    return clazz;
}

jmethodID JNI::findMethod(jclass clazz, const char *name, const char *signature)
{
    if (!clazz || !name || !signature) {
        throw JniException("Required parameter is missing in findMethod()");
    }
    auto mid = _env->GetMethodID(clazz, name, signature);
    checkForJniFailure("GetMethodId");
    return mid;
}

jmethodID JNI::findStaticMethod(jclass clazz, const char * name, const char * signature)
{
    if (!clazz || !name || !signature) {
        throw JniException("Required parameter is missing in findStaticMethod()");
    }
    auto mid = _env->GetStaticMethodID(clazz, name, signature);
    checkForJniFailure("GetStaticMethodID");
    return mid;
}

jfieldID JNI::findField(jclass clazz, const char * name, const char * signature)
{
    if (!clazz || !name || !signature) {
        throw JniException("Required parameter is missing in findField()");
    }
    auto fid = _env->GetFieldID(clazz, name, signature);
    checkForJniFailure("GetFieldID");
    return fid;
}

jfieldID JNI::findStaticField(jclass clazz, const char * name, const char * signature)
{
    if (!clazz || !name || !signature) {
        throw JniException("Required parameter is missing in findStaticField()");
    }
    auto fid = _env->GetStaticFieldID(clazz, name, signature);
    checkForJniFailure("GetStaticFieldID");
    return fid;
}

// Other

jobject JNI::makeGlobal(jobject object)
{
    auto global_ref = _env->NewGlobalRef(object);
    checkForJniFailure("NewGlobalRef");
    try {
        _env->DeleteLocalRef(object);
        checkForJniFailure("DeleteLocalRef");
        return global_ref;
    } catch (...) {
        // Delete global reference.
        _env->DeleteGlobalRef(global_ref);
        std::rethrow_exception(std::current_exception());
    }
}

void JNI::releaseObject(jobject object)
{
    if (object) {
        const char * func_name;
        switch (_env->GetObjectRefType(object)) {
            case JNILocalRefType:
                _env->DeleteLocalRef(object);
                func_name = "DeleteLocalRef";
                break;
            case JNIGlobalRefType:
                _env->DeleteGlobalRef(object);
                func_name = "DeleteGlobalRef";
                break;
            case JNIWeakGlobalRefType:
                _env->DeleteWeakGlobalRef(object);
                func_name = "DeleteWeakGlobalRef";
                break;
            default:
                // Ignore invalid ref type
                func_name = nullptr;
                break;
        }
        if (func_name) {
            // JNI call executed, check for failure.
            checkForJniFailure(func_name);
        }
    }
}

bool JNI::isEqual(jobject obj1, jobject obj2)
{
    return _env->IsSameObject(obj1, obj2);
}

bool JNI::isInstanceOf(jobject object, jclass clazz)
{
    if (!object || !clazz) {
        return false;
    }
    return _env->IsInstanceOf(object, clazz);
}

bool JNI::isExactObjectType(jobject object, jclass clazz)
{
    if (!object || !clazz) {
        return false;
    }
    auto object_clazz = _env->GetObjectClass(object);
    return _env->IsSameObject(object_clazz, clazz);
}

// Exceptions

void JNI::throwToJava(const JniJavaException& exception)
{
    releaseOnFail();

    if (_env->ExceptionOccurred() != exception.throwable()) {
        _env->Throw(exception.throwable());
    }
}

void JNI::throwToJava(const JniException& exception)
{
   // Throw IllegalStateException
   throwToJava(globalOrFatal().commonSpecs().illegalStateException.classRef, exception.message());
}

void JNI::throwToJava(const std::invalid_argument& exception)
{
    // Throw IllegalStateException
    throwToJava(globalOrFatal().commonSpecs().illegalArgumentException.classRef, exception.what());
}

void JNI::throwToJava(jclass clazz, const std::string& message)
{
    releaseOnFail();

    _env->ThrowNew(clazz, message.c_str());
}

void JNI::throwToJava(JniMethod constructor, ...)
{
    releaseOnFail();

    va_list args;
    va_start(args, constructor);
    auto throwable = (jthrowable) createObject(constructor, args).object();
    va_end(args);
    _env->Throw(throwable);
}

void JNI::noThrow(bool release_registered_handles)
{
    if (release_registered_handles) {
        releaseOnFail();
    }
    _env->ExceptionClear();
}

void JNI::wrapCurrentThrowable [[noreturn]] (const char * jni_call)
{
    auto throwable = _env->ExceptionOccurred();
    if (!throwable) {
        throw JniException("wrapCurrentThrowable() failed, because there's no exception set");
    }
    auto message = "JNI call \"" + std::string(jni_call) + "\" failed";
    throw JniJavaException(throwable, message, nullptr);
}

void JNI::checkForJniFailure(const char *jni_call)
{
    if (_env->ExceptionCheck()) {
        wrapCurrentThrowable(jni_call);
    }
}

bool JNI::processException(std::exception_ptr exception)
{
    try {
        // re-throw to investigate the cause
        std::rethrow_exception(exception);
    } catch (JniJavaException &e) {
        throwToJava(e);
        return true;
    } catch (JniException &e) {
        throwToJava(e);
        return true;
    } catch (JniFatalException & e) {
        // Raise fatal error
        _env->FatalError(e.what());
        return true;
    } catch (std::invalid_argument &e) {
        throwToJava(e);
        return true;
    } catch (...) {
        // Unknown exception, Otherwise just release registered handles
        releaseOnFail();
        return false;
    }
}

void JNI::releaseOnFail()
{
    global().objectRegister().removeObjects(_release_on_fail);
    _release_on_fail.clear();
}

// MARK: - JniObject

// setters

void JniObject::setLong(jfieldID field, jlong value)
{
    _jni->env()->SetLongField(_object, field, value);
    _jni->checkForJniFailure("SetLongField");
}

void JniObject::setInt(jfieldID field, jint value)
{
    _jni->env()->SetIntField(_object, field, value);
    _jni->checkForJniFailure("SetIntField");
}

void JniObject::setBoolean(jfieldID field, jboolean value)
{
    _jni->env()->SetBooleanField(_object, field, value);
    _jni->checkForJniFailure("SetBooleanField");
}

void JniObject::setChar(jfieldID field, jchar value)
{
    _jni->env()->SetCharField(_object, field, value);
    _jni->checkForJniFailure("SetCharField");
}

void JniObject::setShort(jfieldID field, jshort value)
{
    _jni->env()->SetShortField(_object, field, value);
    _jni->checkForJniFailure("SetShortField");
}

void JniObject::setFloat(jfieldID field, jfloat value)
{
    _jni->env()->SetFloatField(_object, field, value);
    _jni->checkForJniFailure("SetFloatField");
}

void JniObject::setDouble(jfieldID field, jdouble value)
{
    _jni->env()->SetDoubleField(_object, field, value);
    _jni->checkForJniFailure("SetDoubleField");
}

void JniObject::setObject(jfieldID field, jobject value)
{
    _jni->env()->SetObjectField(_object, field, value);
    _jni->checkForJniFailure("SetObjectField");
}

void JniObject::setString(jfieldID field, const std::string& value)
{
    setObject(field, _jni->toJava(value));
}

void JniObject::setStringNullable(jfieldID field, const std::string& value)
{
    setObject(field, _jni->toJavaNullable(value));
}

void JniObject::setByteArray(jfieldID field, const ByteRange& value)
{
    setObject(field, _jni->toJava(value));
}

void JniObject::setByteArrayNullable(jfieldID field, const ByteRange& value)
{
    setObject(field, _jni->toJavaNullable(value));
}

// getters

jlong JniObject::getLong(jfieldID field)
{
    auto result = _jni->env()->GetLongField(_object, field);
    _jni->checkForJniFailure("GetLongField");
    return result;
}

jint JniObject:: getInt(jfieldID field)
{
    auto result = _jni->env()->GetIntField(_object, field);
    _jni->checkForJniFailure("GetIntField");
    return result;
}

jboolean JniObject::getBoolean(jfieldID field)
{
    auto result = _jni->env()->GetBooleanField(_object, field);
    _jni->checkForJniFailure("GetBooleanField");
    return result;
}

jchar JniObject::getChar(jfieldID field)
{
    auto result = _jni->env()->GetCharField(_object, field);
    _jni->checkForJniFailure("GetCharField");
    return result;
}

jshort JniObject::getShort(jfieldID field)
{
    auto result = _jni->env()->GetShortField(_object, field);
    _jni->checkForJniFailure("GetShortField");
    return result;
}

jfloat JniObject::getFloat(jfieldID field)
{
    auto result = _jni->env()->GetFloatField(_object, field);
    _jni->checkForJniFailure("GetFloatField");
    return result;
}

jdouble JniObject::getDouble(jfieldID field)
{
    auto result = _jni->env()->GetDoubleField(_object, field);
    _jni->checkForJniFailure("GetDoubleField");
    return result;
}

jobject JniObject::getObject(jfieldID field)
{
    auto result = _jni->env()->GetObjectField(_object, field);
    _jni->checkForJniFailure("GetObjectField");
    return result;
}

std::string JniObject::getString(jfieldID field)
{
    return _jni->fromJava((jstring) getObject(field));
}

ByteArray JniObject::getByteArray(jfieldID field)
{
    return _jni->fromJava((jbyteArray) getObject(field));
}

ByteArray JniObject::getStringAsBytes(jfieldID field)
{
    return _jni->fromJavaStringToBytes((jstring) getObject(field));
}


// MARK: - JniObjectArray

void JniObjectArray::setObject(jsize index, jobject object)
{
    _jni->env()->SetObjectArrayElement(_array, index, object);
    _jni->checkForJniFailure("SetObjectArrayElement");
}

jobject JniObjectArray::getObject(jsize index)
{
    auto object = _jni->env()->GetObjectArrayElement(_array, index);
    _jni->checkForJniFailure("GetObjectArrayElement");
    return object;
}

} // namespace cc7::jni
