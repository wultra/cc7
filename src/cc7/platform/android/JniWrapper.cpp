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
#include <cc7/Utilities.h>

namespace cc7::jni {

// MARK: - JNIGlobal

std::once_flag JNIGlobal::s_init_flag;
std::unique_ptr<JNIGlobal> JNIGlobal::s_instance;

#define SAFE_ARGS(name, param)                              \
    va_list name;                                           \
    va_start(name, param);                                  \
    cc7::utilities::VaListGuard _guard_ ## name { name };

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
            s_instance = std::unique_ptr<JNIGlobal>(new JNIGlobal(temporary));

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
    _specs(JniCommon::buildSpecs(jni))
{
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

const JniCommon& JNI::commonSpecs()
{
    return global().commonSpecs();
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

JniObjectArray JNI::createObjectArray(jclass item_clazz, size_t size, bool null_if_empty)
{
    jobjectArray array;
    if (size && !null_if_empty) {
        array = _env->NewObjectArray((jsize) size, item_clazz, nullptr);
        checkForJniFailure("NewObjectArray");
    } else {
        array = nullptr;
    }
    return { this, (jsize) size, array };
}

// Objects

JniObject JNI::createObject(JniMethod constructor, ...)
{
    SAFE_ARGS(args, constructor)
    return createObjectV(constructor, args);
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
        return createObject(spec.initHandle, handle);
    } catch (...) {
        // Delete registered instance and re-throw exception.
        reg.removeObject(handle);
        std::rethrow_exception(std::current_exception());
    }
}

JniCommon::NativeHandleClass JNI::buildNativeHandleSpec(const char * class_name)
{
    auto this_class = getClass(class_name);
    auto constructor = this_class.findMethod("<init>", "(J)V");
    jfieldID handle_field = this_class.findField("nativeObjectHandle", "J");
    auto global_this = this_class.makeGlobal();
    return {
        global_this,
        { global_this, constructor },
        handle_field,
        class_name
    };
}

// Class management

JniClass JNI::getClass(const char * class_name)
{
    return { this, findClass(class_name) };
}

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

// Enumerations

JniCommon::ConstantSetSpec JNI::buildConstantSetSpec(const char * class_name, std::initializer_list<const char*> fields)
{
    auto clazz = getClass(class_name);
    std::unordered_set<jint> values;
    for (auto field_name : fields) {
        auto field_id = clazz.findStaticField(field_name, "I");
        auto field_value = clazz.getInt(field_id);
        if (values.find(field_value) != values.end()) {
            throw JniException(std::string("Value of static field is duplicit: ") + field_name);
        }
        values.insert(field_value);
    }
    return { clazz.makeGlobal(), class_name, values };
}

JniCommon::ConstantRangeSpec JNI::buildConstantRangeSpec(const char * class_name, const char * bottom_field, const char * top_field)
{
    auto clazz = getClass(class_name);
    auto bottom_value = clazz.getInt(clazz.findStaticField(bottom_field, "I"));
    auto top_value = clazz.getInt(clazz.findStaticField(top_field, "I"));
    if (bottom_value > top_value) {
        throw JniException(std::string("Bottom value is greater than top value. Field names: ") + bottom_field + ", " + top_field);
    }
    return { clazz.makeGlobal(), class_name, bottom_value, top_value };
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

void JNI::releaseSpec(JniCommon::NativeHandleClass& spec)
{
    releaseObject(spec.classRef);
    spec.classRef = nullptr;
}

void JNI::releaseSpec(JniCommon::ConstantSetSpec& spec)
{
    releaseObject(spec.classRef);
    spec.classRef = nullptr;
}

void JNI::releaseSpec(JniCommon::ConstantRangeSpec& spec)
{
    releaseObject(spec.classRef);
    spec.classRef = nullptr;
}

void JNI::releaseSpec(JniCommon::ExceptionSpec& spec)
{
    releaseObject(spec.classRef);
    spec.classRef = nullptr;
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

    _env->Throw(exception.throwable());
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

    SAFE_ARGS(args, constructor)
    auto throwable = (jthrowable) createObject(constructor, args).object();
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
    std::string exception_msg;
    try {
        exception_msg = JniObject(this, throwable).callString(commonSpecs().throwable.methods.getMessage);
    } catch (...) {
        exception_msg = "Failed to extract message from java/lang/Throwable";
        _env->ExceptionClear();
    }
    auto message = "JNI call \"" + std::string(jni_call) + "\" failed: " + exception_msg;
    throw JniJavaException(throwable, message, nullptr);
}

void JNI::checkForJniFailure(const char *jni_call)
{
    if (_env->ExceptionCheck()) {
        wrapCurrentThrowable(jni_call);
    }
}

bool JNI::processException(std::exception_ptr exception, bool custom_argument_exception)
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
        if (custom_argument_exception) {
            throwToJava(e);
            return true;
        }
        // Exception is not handled
    } catch (...) {
        // Unknown exception
    }
    // Unknown or unhandled exception, Otherwise just release registered handles
    releaseOnFail();
    return false;
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

jbyte JniObject::getByte(jfieldID field)
{
    auto result = _jni->env()->GetByteField(_object, field);
    _jni->checkForJniFailure("GetByteField");
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

// calls

void JniObject::callVoid(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    _jni->env()->CallVoidMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallVoidMethodV");
}

jlong JniObject::callLong(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallLongMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallLongMethodV");
    return result;
}

jint JniObject::callInt(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallIntMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallIntMethodV");
    return result;
}

jboolean JniObject::callBoolean(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallBooleanMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallBooleanMethodV");
    return result;
}

jchar JniObject::callChar(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallCharMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallCharMethodV");
    return result;
}

jbyte JniObject::callByte(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallByteMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallByteMethodV");
    return result;
}

jshort JniObject::callShort(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallShortMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallShortMethodV");
    return result;
}

jfloat JniObject::callFloat(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallFloatMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallFloatMethodV");
    return result;
}

jdouble JniObject::callDouble(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    auto result = _jni->env()->CallDoubleMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallDoubleMethodV");
    return result;
}

jobject JniObject::callObjectV(JniMethod method, va_list args)
{
    auto result = _jni->env()->CallObjectMethodV(_object, method.methodId, args);
    _jni->checkForJniFailure("CallObjectMethodV");
    return result;
}

jobject JniObject::callObject(JniMethod method, ...)
{
    SAFE_ARGS(args, method);
    return callObjectV(method, args);
}

std::string JniObject::callString(JniMethod method, ...)
{
    SAFE_ARGS(args, method)
    return _jni->fromJava((jstring) callObjectV(method, args));
}

ByteArray JniObject::callByteArray(JniMethod method, ...)
{
    SAFE_ARGS(args, method)
    return _jni->fromJava((jbyteArray) callObjectV(method, args));
}


// MARK: - JniClass

jclass JniClass::makeGlobal()
{
    if (isNull()) {
        return nullptr;
    }
    return (jclass) _jni->makeGlobal(_clazz);
}

jfieldID JniClass::findField(const char * name, const char * signature)
{
    return _jni->findField(_clazz, name, signature);
}

jfieldID JniClass::findStaticField(const char * name, const char * signature)
{
    return _jni->findStaticField(_clazz, name, signature);
}

jmethodID JniClass::findMethod(const char * name, const char * signature)
{
    return _jni->findMethod(_clazz, name, signature);
}

jmethodID JniClass::findStaticMethod(const char * name, const char * signature)
{
    return _jni->findStaticMethod(_clazz, name, signature);
}

jlong JniClass::getLong(jfieldID field)
{
    auto value = _jni->env()->GetStaticLongField(_clazz, field);
    _jni->checkForJniFailure("GetStaticLongField");
    return value;
}

jint JniClass::getInt(jfieldID field)
{
    auto value = _jni->env()->GetStaticIntField(_clazz, field);
    _jni->checkForJniFailure("GetStaticIntField");
    return value;
}

jboolean JniClass::getBoolean(jfieldID field)
{
    auto value = _jni->env()->GetStaticIntField(_clazz, field);
    _jni->checkForJniFailure("GetStaticIntField");
    return value;
}

jchar JniClass::getChar(jfieldID field)
{
    auto value = _jni->env()->GetStaticCharField(_clazz, field);
    _jni->checkForJniFailure("GetStaticCharField");
    return value;
}

jbyte JniClass::getByte(jfieldID field)
{
    auto value = _jni->env()->GetStaticByteField(_clazz, field);
    _jni->checkForJniFailure("GetStaticByteField");
    return value;
}

jshort JniClass::getShort(jfieldID field)
{
    auto value = _jni->env()->GetStaticShortField(_clazz, field);
    _jni->checkForJniFailure("GetStaticShortField");
    return value;
}

jfloat JniClass::getFloat(jfieldID field)
{
    auto value = _jni->env()->GetStaticFloatField(_clazz, field);
    _jni->checkForJniFailure("GetStaticFloatField");
    return value;
}

jdouble JniClass::getDouble(jfieldID field)
{
    auto value = _jni->env()->GetStaticDoubleField(_clazz, field);
    _jni->checkForJniFailure("GetStaticDoubleField");
    return value;
}

jobject JniClass::getObject(jfieldID field)
{
    auto value = _jni->env()->GetStaticObjectField(_clazz, field);
    _jni->checkForJniFailure("GetStaticObjectField");
    return value;
}

std::string JniClass::getString(jfieldID field)
{
    return _jni->fromJava((jstring) getObject(field));
}

ByteArray JniClass::getByteArray(jfieldID field)
{
    return _jni->fromJava((jbyteArray) getObject(field));
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
