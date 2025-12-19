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

#include <cc7/ByteArray.h>
#include <cc7/jni/JniCommon.h>
#include <cc7/jni/JniException.h>
#include <cc7/jni/JniObjectRegister.h>
#include <cc7/jni/JniJson.h>
#include <functional>

namespace cc7::jni {

class JNI;
class JNIGlobal;

/// The `JniObject` is a thin wrapper that allows you simplify access to object's fields.
class JniObject
{
public:
    /// Returns information whether object is null.
    bool isNull() const noexcept { return _object == nullptr; }

    /// Automatic casting to jobject
    operator jobject () const { return _object; }
    /// Get pointer to java object.
    jobject object() const { return _object; }
    /// Conversion to bool, just like a raw pointer
    operator bool() const noexcept { return _object != nullptr; }
    /// Unsafe cast object pointer to to java object array.
    jobjectArray objectArray() const { return (jobjectArray) _object; }
    /// Unsafe cast object pointer to java byte array.
    jbyteArray byteArray() const { return (jbyteArray) _object; }
    /// Unsafe cast object pointer to java string.
    jstring string() const { return (jstring) _object; }

    // setters

    /// Set long value to given field.
    void setLong(jfieldID field, jlong value);
    /// Set int value to given field.
    void setInt(jfieldID field, jint value);
    /// Set boolean value to given field.
    void setBoolean(jfieldID field, jboolean value);
    /// Set char  to given field.
    void setChar(jfieldID field, jchar value);
    /// Set short value to given field.
    void setShort(jfieldID field, jshort value);
    /// Set float value to given field.
    void setFloat(jfieldID field, jfloat value);
    /// Set double value to given field.
    void setDouble(jfieldID field, jdouble value);
    /// Set object value to given field.
    void setObject(jfieldID field, jobject value);
    /// Set string value to given field.
    void setString(jfieldID field, const std::string& value);
    /// Set nullable string value to given field. If value is empty, then null is set.
    void setStringNullable(jfieldID field, const std::string& value);
    /// Set byte array to given field.
    void setByteArray(jfieldID field, const ByteRange& value);
    /// Set nullable byte array to given field. If value is empty, then null is set.
    void setByteArrayNullable(jfieldID field, const ByteRange& value);

    // getters

    /// Get long value from the field.
    jlong getLong(jfieldID field);
    /// Get int value from the field.
    jint getInt(jfieldID field);
    /// Get boolean value from the field.
    jboolean getBoolean(jfieldID field);
    /// Get char value from the field.
    jchar getChar(jfieldID field);
    /// Get byte value from the field.
    jbyte getByte(jfieldID field);
    /// Get short value from the field.
    jshort getShort(jfieldID field);
    /// Get float value from the field.
    jfloat getFloat(jfieldID field);
    /// Get double value from the field.
    jdouble getDouble(jfieldID field);
    /// Get object value from the field.
    JniObject getObject(jfieldID field);
    /// Get string value from the field.
    std::string getString(jfieldID field);
    /// Get byte array value from the field.
    ByteArray getByteArray(jfieldID field);
    /// Get string value from the field and reinterpret the string as byte array.
    ByteArray getStringAsBytes(jfieldID field);

    // Delete copy/move to avoid accidental dangling JNI/JNIEnv pointer
    JniObject(const JniObject&) = delete;
    JniObject(JniObject&&) = delete;
    JniObject& operator=(const JniObject&) = delete;
    JniObject& operator=(JniObject&&) = delete;

    /// Call Java method returning void.
    void callVoid(JniMethod method, ...);
    /// Call Java method returning "long" value type.
    jlong callLong(JniMethod method, ...);
    /// Call Java method returning "int" value type.
    jint callInt(JniMethod method, ...);
    /// Call Java method returning "boolean" value type.
    jboolean callBoolean(JniMethod method, ...);
    /// Call Java method returning "char" value type.
    jchar callChar(JniMethod method, ...);
    /// Call Java method returning "byte" value type.
    jbyte callByte(JniMethod method, ...);
    /// Call Java method returning "short" value type.
    jshort callShort(JniMethod method, ...);
    /// Call Java method returning "float" value type.
    jfloat callFloat(JniMethod method, ...);
    /// Call Java method returning "double" value type.
    jdouble callDouble(JniMethod method, ...);
    /// Call Java method returning "any" object.
    JniObject callObject(JniMethod method, ...);
    /// Call Java method returning "any" object.
    JniObject callObjectV(JniMethod method, va_list args);
    /// Call Java method returning "String" value type.
    std::string callString(JniMethod method, ...);
    /// Call Java method returning "byte[]" value type.
    ByteArray callByteArray(JniMethod method, ...);

    /// Release object reference.
    void release();

    /// Release local object reference.
    void releaseLocal();

private:
    friend class JNI;
    friend class JniClass;

    /// Construct object with pointer to JNI class and object itself.
    JniObject(JNI * jni, jobject object) : _jni(jni), _object(object) {}

    JNI * _jni;
    jobject _object;
};

/// The `JniClass` is a thin wrapper that allows you simplify access to class' static fields.
class JniClass
{
public:
    /// Returns information whether object is null.
    bool isNull() const noexcept { return _clazz == nullptr; }

    /// Automatic casting to jobject
    operator jclass () const { return _clazz; }
    /// Get pointer to java object.
    jclass clazz() const { return _clazz; }
    /// Conversion to bool, just like a raw pointer
    operator bool() const noexcept { return _clazz != nullptr; }

    /// Make global reference from class stored in this object. If captured class is null, then returns null.
    jclass makeGlobal();

    // Field / Method lookup

    /// Find instance method in the class.
    /// @param name Name of the instance method. If you're looking for constructor, use "<init>".
    /// @param signature Signature of the instance method.
    /// @return Information about the instance method.
    jmethodID findMethod(const char * name, const char * signature);

    /// Find static method in the class.
    /// @param name Name of the static method.
    /// @param signature Signature of the static method.
    /// @return Information about the static method.
    jmethodID findStaticMethod(const char * name, const char * signature);

    /// Find instance field in the class.
    /// @param name Name of the instance field.
    /// @param signature Signature of the instance field.
    /// @return Information about the instance field.
    jfieldID findField(const char * name, const char * signature);

    /// Find static field in the class.
    /// @param name Name of the static field.
    /// @param signature Signature of the static field.
    /// @return Information about the static field.
    jfieldID findStaticField(const char * name, const char * signature);

    // Static field getters

    /// Get long value from the static field.
    jlong getLong(jfieldID field);
    /// Get int value from the static field.
    jint getInt(jfieldID field);
    /// Get boolean value from the static field.
    jboolean getBoolean(jfieldID field);
    /// Get char value from the static field.
    jchar getChar(jfieldID field);
    /// Get byte value from the static field.
    jbyte getByte(jfieldID field);
    /// Get short value from the static field.
    jshort getShort(jfieldID field);
    /// Get float value from the static field.
    jfloat getFloat(jfieldID field);
    /// Get double value from the static field.
    jdouble getDouble(jfieldID field);
    /// Get object value from the static field.
    JniObject getObject(jfieldID field);
    /// Get string value from the static field.
    std::string getString(jfieldID field);
    /// Get byte array value from the static field.
    ByteArray getByteArray(jfieldID field);


    // Delete copy/move to avoid accidental dangling JNI/JNIEnv pointer
    JniClass(const JniObject&) = delete;
    JniClass(JniObject&&) = delete;
    JniClass& operator=(const JniObject&) = delete;
    JniClass& operator=(JniObject&&) = delete;

private:
    friend class JNI;

    /// Construct class wrapper.
    /// @param jni Pointer to JNI object.
    /// @param size Size of array.
    /// @param array jobjectArray object.
    JniClass(JNI * jni, jclass clazz) : _jni(jni), _clazz(clazz) {}
    JNI * _jni;
    jclass _clazz;
};

/// The `JniObjectArray` is a thin wrapper that allows you simplify access to array of objects.
class JniObjectArray
{
public:
    // Delete copy/move to avoid accidental dangling JNIEnv pointer
    JniObjectArray(const JniObjectArray&) = delete;
    JniObjectArray(JniObjectArray&&) = delete;
    JniObjectArray& operator=(const JniObjectArray&) = delete;
    JniObjectArray& operator=(JniObjectArray&&) = delete;

    /// Returns `true` if array is null or empty.
    bool isEmpty() const noexcept { return _array == nullptr || _size == 0; }
    /// Returns number of items stored in the array.
    jsize size() const noexcept { return _size; }

    /// Set object at given index.
    void setObject(jsize index, jobject object);
    /// Get object from given index.
    jobject getObject(jsize index);

    // Automatic casting to jobject
    operator jobject () const noexcept { return (jobject) _array; }
    jobject object() const noexcept { return  (jobject) _array; }

    // Automatic casting to jobjectArray
    operator jobjectArray () const noexcept { return _array; }
    jobjectArray array() const noexcept { return _array; }

private:
    friend class JNI;

    /// Construct array wrapper.
    /// @param jni Pointer to JNI object.
    /// @param size Size of array.
    /// @param array jobjectArray object.
    JniObjectArray(JNI * jni, jsize size, jobjectArray array) : _jni(jni), _size(size), _array(array) {}
    JNI * _jni;
    jsize _size;
    jobjectArray _array;
};

// MARK: - JNIGlobal

/// The `JNIGlobal` class provides access to shared data required for a JNI wrapper functionality.
class JNIGlobal
{
public:
    /// Type of function that can be called after `JNIGlobal` instance is initialized.
    /// You can typically add your own java class caching functionality into the global initializer.
    /// Be aware, that if initialization function throws an exception, then the fatal failure is reported
    /// back to Java environment.
    typedef std::function<void(JNI& jni)> GlobalInitializer;

    /// Add global initialization function called when `JNIGlobal` instance is registered.
    /// @param initializer Initializer function.
    static void addGlobalInitializer(const GlobalInitializer& initializer);

    /// Get reference to `JNIGlobal` singleton instance. The instance is initialized when it's accessed for first time.
    /// @param env JNIEnv context valid for the current thread.
    /// @return Reference to singleton `JNIGlobal` instance.
    static JNIGlobal& global(JNIEnv * env);

    /// Get `JNI` wrapper object
    /// @param env JNIEnv context valid for the current thread.
    /// @param local_ref_capacity Alter capacity of local object references reserved for the current JNI execution frame.
    ///                           If zero is provided, then the default value is applied. The JNI system guarantees at least 16 objects available.
    /// @return `JNI` object instance valid for the current thread.
    static JNI local(JNIEnv * env, jint local_ref_capacity = 0);

    /// Returns reference to `JniCommon` structure, containing information about common Java classes, widely used in the system.
    const JniCommon& commonSpecs() const noexcept { return _specs; }

    /// Returns const reference to `JniObjectRegister` class providing translation from handle to shared_ptr<T> instance.
    const JniObjectRegister& objectRegister() const noexcept { return _object_register; }
    /// Returns reference to `JniObjectRegister` class providing translation from handle to shared_ptr<T> instance.
    JniObjectRegister& objectRegister() noexcept { return _object_register; }

private:

    JNIGlobal(JNI& jni);

    JniCommon _specs;
    JniObjectRegister _object_register;

    static std::once_flag s_init_flag;
    static std::unique_ptr<JNIGlobal> s_instance;
};

/// The `JNI` class is a thin wrapper that provides conversion of various types from and to Java environment.
class JNI
{
public:
    // Delete copy/move to avoid accidental dangling JNIEnv pointer
    JNI(const JNI&) = delete;
    JNI(JNI&&) = delete;
    JNI& operator=(const JNI&) = delete;
    JNI& operator=(JNI&&) = delete;

    // Automatic casting to JNIEnv
    operator JNIEnv* () const noexcept { return _env; }
    JNIEnv * env() const noexcept { return _env; }

    // Parameter check

    /// Test whether the provided parameter is not null. If parameter is `null`, then `std::invalid_argument` is raised.
    /// @param object Input parameter.
    /// @param param_name Name of parameter, used in the raised exception.
    void requireParameter(jobject object, const char * param_name);

    // bytes

    /// Convert `jbyteArray` value into `cc7::ByteArray`.
    ByteArray fromJava(jbyteArray array);
    /// Convert `jstring` value into `cc7::ByteArray.
    ByteArray fromJavaStringToBytes(jstring string);
    /// Convert `cc7::ByteRange` into `jbyteArray`.
    jbyteArray toJava(const ByteRange& range);
    /// Convert `cc7::ByteRange` into nullable `jbyteArray`. If the range is empty, then `null` is returned.
    jbyteArray toJavaNullable(const ByteRange& range);

    // Arrays

    /// Convert `jlongArray` value into `vector<int64_t>`.
    std::vector<int64_t> fromJava(jlongArray array);

    /// Convert `vector<int64_t>` value into `jlongArray`.
    jlongArray toJava(const std::vector<int64_t>& vector);

    // string

    /// Convert `jstring` value into `std::string`.
    std::string fromJava(jstring string);
    /// Convert nul terminated C string into `jstring`.
    jstring toJava(const char* string);
    /// Convert `std::string` value into `jstring`.
    jstring toJava(const std::string& string);
    /// Convert `std::string_view` value into `jstring`.
    jstring toJava(const std::string_view& string);
    /// Convert `std::string` into `jstring`. If string is empty, then `null` is returned.
    jstring toJavaNullable(const std::string& string);
    /// Convert `std::string_view` into `jstring`. If string is empty, then `null` is returned.
    jstring toJavaNullable(const std::string_view& string);

    // Arrays

    /// Convert `jobjectArray` into `JniObjectArray` wrapper.
    JniObjectArray fromJava(jobjectArray array);

    /// Create `jobjectArray` with the requested size.
    JniObjectArray createObjectArray(jclass item_clazz, size_t size, bool null_if_empty = false);

    // TODO: Other array types?

    // Objects

    /// Create new instance of Java object.
    /// @param constructor Method specifying object's constructor.
    /// @param ... Parameters passed to the constructor.
    /// @return `JniObject` wrapper with created Java object.
    JniObject createObject(JniInitMethod constructor, ...);

    /// Create new instance of Java object.
    /// @param constructor  Method specifying object's constructor.
    /// @param args Parameters passed to the constructor.
    /// @return `JniObject` wrapper with created Java object.
    JniObject createObjectV(const JniInitMethod& constructor, va_list args);

    /// Convert input instance of Java object into `JniObject` wrapper.
    /// @param object jobject to wrap into `JniObject`.
    /// @param clazz If non-null is provided, then object must be the same class.
    /// @return `JniObject` wrapper with captured jobject instance.
    JniObject fromJava(jobject object, jclass clazz = nullptr);

    // Handle based objects

    /// Return smart pointer with instance of C++ object previously registered in the object register.
    /// @tparam T Type of C++ object.
    /// @param handle Previously registered handle.
    /// @return Smart pointer with instance of C++ object previously registered in the object register.
    template<class T> std::shared_ptr<T> fromHandle(jlong handle)
    {
        return global().objectRegister().getTypedObject<T>(handle);
    }

    /// Register the provided C++ object and returns its registration handle.
    /// @param object C++ object to register.
    /// @param release_on_exception If `true`, which is default value, then the registered handle is automatically removed
    ///        from the register if exception occurs during the native code execution. This cleanup works only if you use
    ///        `processException()` method for the exception processing.
    /// @return Unique handle assigned to the given instance of C++ object.
    template <typename T> jlong toHandle(const std::shared_ptr<T>& object, bool release_on_exception = true);

    /// Convert the provided C++ object into Java object. The object must fulfill `JniCommon::NativeHandleClass` class specification.
    /// @param spec Java object specification.
    /// @param object C++ object.
    /// @return Java object created from C++ object.
    template <typename T> jobject toJava(const JniCommon::NativeHandleClass& spec, const std::shared_ptr<T>& object);

    /// Convert Java object into typed C++ object with using given `JniCommon::NativeHandleClass` specification.
    /// @tparam T Type of C++ object.
    /// @param spec Java object specification.
    /// @param object Java object to convert.
    /// @return Smart pointer with given
    template<class T> std::shared_ptr<T> fromJava(const JniCommon::NativeHandleClass& spec, jobject object);

    /// Build specification structure for Java object wrapping a native C++ object.
    /// @param class_name Java class name.
    /// @return `NativeHandleClass` specification.
    JniCommon::NativeHandleClass buildNativeHandleSpec(const char * class_name);

    /// Check whether handle represents a `null` object.
    /// @param handle Handle to test.
    /// @return true if handle represents `null` object
    static bool isNullHandle(jlong handle) noexcept { return handle == NULL_HANDLE; }

    /// Constant for handle representing a `null` object.
    static const jlong NULL_HANDLE = JniObjectRegister::NULL_ID;

    /// Remove C++ object registered in global register.
    /// @param handle Object's handle.
    void removeHandle(jlong handle);

    // Class management

    /// Wrap existing class reference into JniClass.
    /// @param clazz Class to wrap.
    /// @return Class wrapped in JniClass object.
    JniClass fromJava(jclass clazz);

    /// Find Java class by its name and return JniClass wrapper object.
    /// @param class_name Class name to find. Use slashes in naming, such as "java/lang/String".
    /// @return JniClass wrapper object.
    JniClass getClass(const char * class_name);

    /// Find Java class by its name.
    /// @param class_name Class name to find. Use slashes in naming, such as "java/lang/String".
    /// @return Information about the class.
    jclass findClass(const char * class_name);

    /// Find instance method in the class.
    /// @param clazz Information about the class.
    /// @param name Name of the instance method. If you're looking for constructor, use "<init>".
    /// @param signature Signature of the instance method.
    /// @return Information about the instance method.
    jmethodID findMethod(jclass clazz, const char * name, const char * signature);

    /// Find static method in the class.
    /// @param clazz Information about the class.
    /// @param name Name of the static method.
    /// @param signature Signature of the static method.
    /// @return Information about the static method.
    jmethodID findStaticMethod(jclass clazz, const char * name, const char * signature);

    /// Find instance field in the class.
    /// @param clazz Information about the class.
    /// @param name Name of the instance field.
    /// @param signature Signature of the instance field.
    /// @return Information about the instance field.
    jfieldID findField(jclass clazz, const char * name, const char * signature);

    /// Find static field in the class.
    /// @param clazz Information about the class.
    /// @param name Name of the static field.
    /// @param signature Signature of the static field.
    /// @return Information about the static field.
    jfieldID findStaticField(jclass clazz, const char * name, const char * signature);

    /// Build class specification structure for the given Java class.
    ///
    /// The template type T must conform to the following requirements:
    /// - T must be a standard layout structure (e.g. no subclassing, no virtual method, etc.)
    /// - T::Methods nested structure must be defined. This nested structure also must conform to the standard layout.
    ///   The structure typically contains `JniInitMethod` or `JniMethod` fields with all instance or static methods you're plan to call from JNI.
    /// - T must contain `static constexpr JniMethodSpec methodSpecs[]` static field with the method specifications.
    /// - T::Fields nested structure must be defined.  This nested structure also must conform to the standard layout.
    ///   The structure typically contains `jfieldID` fields with all instance or static fields you're plan to use from JNI.
    /// - T must contain `static constexpr JniFieldSpec fieldSpecs[]` static field with the field specifications.
    /// - T must contain `jclass classRef` field.
    /// - T must contain `T::Method methods` field.
    /// - T must contain `T::Fields fields` field.
    ///
    /// See `JniCommon` structure which contains examples of specifications for a various common Java objects.
    ///
    /// @tparam T Class specification structure type.
    /// @param class_name Name of the java class to resolve.
    /// @return T with initialized information about the class.
    template<typename T> T buildClassSpec(const char * class_name);

    // Enumerations

    /// Build specification structure for integer constants extracted from given Java class.
    /// @param class_name Class name that contains static fields with integer constants.
    /// @param fields List with fields.
    /// @return Specification structure for integer constants extracted from given Java class.
    JniCommon::ConstantSetSpec buildConstantSetSpec(const char * class_name, std::initializer_list<const char*> fields);

    /// Convert integer value into enumeration. Conversion is specified in `JniCommon::ConstantSetSpec`.
    template<typename T> T fromJava(const JniCommon::ConstantSetSpec& spec, jint value);

    /// Convert enumeration into Java integer. Conversion is specified in `JniCommon::ConstantSetSpec`.
    template<typename T> jint toJava(const JniCommon::ConstantSetSpec& spec, T value);

    /// Build specification structure for integer constants extracted from given Java class.
    /// @param class_name Class name that contains static fields with integer constants.
    /// @param fields List with fields. All fields must lead to an contiguous range of integers, otherwise an error is reported.
    /// @return Specification structure for range of integer constants extracted from given Java class.
    JniCommon::ConstantRangeSpec buildConstantRangeSpec(const char * class_name, std::initializer_list<const char*> fields);

    /// Convert integer value into enumeration. Conversion is specified in `JniCommon::ConstantRangeSpec`.
    template<typename T> T fromJava(const JniCommon::ConstantRangeSpec& spec, jint value);

    /// Convert enumeration into Java integer. Conversion is specified in `JniCommon::ConstantRangeSpec`.
    template<typename T> jint toJava(const JniCommon::ConstantRangeSpec& spec, T value);

    // Other

    /// Convert local object reference to a global reference. The provided local reference is then deleted.
    /// Be aware that if you don't release the global reference in the future, then this will cause a memory leak.
    /// The JNI wrapper is using this method only for keeping information about resolved classes in the cache, during its initialization.
    ///
    /// @param object Local reference to any kind of java object.
    /// @return Global reference.
    jobject makeGlobal(jobject object);

    /// Release any object reference. The method determines the type of reference and then deletes the reference with
    /// appropriate "Delete * Ref" JNI call.
    ///
    /// @param object Reference to object to delete.
    void releaseObject(jobject object);

    /// Release local object reference.
    ///
    /// @param object Local reference to object to delete.
    void releaseLocal(jobject object);

    /// Release multiple local objects.
    /// @param local_objects List of local referenced objects to delete..
    void releaseLocal(std::initializer_list<jobject> local_objects);

    /// Release global references in class specification structure.
    void releaseSpec(JniCommon::NativeHandleClass& spec);

    /// Release global references in class specification structure.
    void releaseSpec(JniCommon::ConstantSetSpec& spec);

    /// Release global references in class specification structure.
    void releaseSpec(JniCommon::ConstantRangeSpec& spec);

    /// Release global references in class specification structure.
    void releaseSpec(JniCommon::ExceptionSpec& spec);
    
    /// Release global references in class specification structure. The T type must
    /// contain `jclass classRef` field.
    template <typename T> void releaseSpec(T& spec) {
        releaseObject(spec.classRef);
        spec.classRef = nullptr;
    }

    /// Tests whether two references refer to the same Java object.
    bool isEqual(jobject obj1, jobject obj2);

    /// Tests whether an object is an instance of a class.
    bool isInstanceOf(jobject object, jclass clazz);

    /// Tests whether an object is an exact instance of a class.
    bool isExactObjectType(jobject object, jclass clazz);

    // Exceptions

    /// Set jthrowable from the `JniJavaException` as a result of JNI call.
    ///
    /// This method is useful only in a final C++ exception processing, when you catch a specific exception
    /// types and you want to marshall such exception into Java exception.
    void throwToJava(const JniJavaException& exception);

    /// Create `IllegalStateException` Java exception from given C++ exception and set it as a result of JNI call.
    ///
    /// This method is useful only in a final C++ exception processing, when you catch a specific exception
    /// types and you want to marshall such exception into Java exception.
    void throwToJava(const JniException& exception);

    /// Create `IllegalArgumentException` Java exception from given C++ exception and set it as a result of JNI call.
    ///
    /// This method is useful only in a final C++ exception processing, when you catch a specific exception
    /// types and you want to marshall such exception into Java exception.
    void throwToJava(const std::invalid_argument& exception);

    /// Create a standard Java exception specified by its class and the message and set it as a result of JNI call.
    ///
    /// This method is useful only in a final C++ exception processing, when you catch a specific exception
    /// types and you want to marshall such exception into Java exception.
    void throwToJava(jclass clazz, const std::string& message);

    /// Create a custom Java exception specified by its constructor and the custom parameters and set it as a result of JNI call.
    ///
    /// This method is useful only in a final C++ exception processing, when you catch a specific exception
    /// types and you want to marshall such exception into Java exception.
    void throwToJava(JniInitMethod constructor, ...);

    /// Clear a possible pending Throwable exception that occurred during the JNI call. The method is useful when you don't want
    /// to report any exception from JNI call execution back to Java. You can decide whether the object handles registered
    /// during the execution are released.
    /// @param release_registered_handles If true (a default value), then all registered object handles will be released.
    void noThrow(bool release_registered_handles = true);

    /// Wrap a throwable exception that occurred during the JNI call and throw C++ exception.
    /// @param jni_call Name of JNI call that caused a failure.
    void wrapCurrentThrowable [[noreturn]] (const char * jni_call);

    /// Check whether the last executed JNI call failed. If yes, then `wrapCurrentThrowable()` method is called.
    /// @param jni_call Name of JNI call that was just executed.
    void checkForJniFailure(const char * jni_call);

    /// Process a C++ exception. You should call this method in your `catch (...) {}` block to properly marshall
    /// a C++ exceptions into Java exceptions. If method doesn't know the type of exception, then returns `false` and you
    /// should execute your own logic in the failure processing.
    ///
    /// @param exception C++ exception to process.
    /// @param custom_argument_exception If `true` then function will not handle a `std::invalid_argument` exception.
    /// @return true if exception was processed, false otherwise. You should apply your own logic of failure processing
    ///         when false is returned.
    bool processException(std::exception_ptr exception = std::current_exception(), bool custom_argument_exception = false);

    /// Get `JNIGlobal` reference associated with this JNI object. Method throws `JniException` if a global instance is
    /// not available. This situation may happen during a `JNIGlobal` instance's initialization sequence.
    JNIGlobal& global();
    /// Get `JNIGlobal` reference associated with this JNI object. Method causes a Java Fatal failure if a global instance is
    /// not available. This situation may happen during a `JNIGlobal` instance's initialization sequence.
    JNIGlobal& globalOrFatal();

    /// Get `JniCommon` reference associated with this JNI object. Method throws `JniException` if a `JNIGlobal` instance is
    /// not available. This situation may happen during a `JNIGlobal` instance's initialization sequence.
    const JniCommon& commonSpecs();

private:
    friend class JNIGlobal;

    JNI(JNIEnv * env, JNIGlobal * global, jint local_ref_capacity);

    JNIEnv *    _env;
    JNIGlobal * _global;

    std::vector<JniObjectRegister::ObjID> _release_on_fail;

    void releaseOnFail();

};

// MARK: buildClassSpec<T>() implementation

// Traits to detect T::Methods, T::Fields structs
// T::Methods
template<typename, typename = void>
    struct has_methods_struct : std::false_type {};
template<typename T>
    struct has_methods_struct<T, std::void_t<typename T::Methods>> : std::true_type {};

// T::Fields
template<typename, typename = void>
    struct has_fields_struct : std::false_type {};
template<typename T>
    struct has_fields_struct<T, std::void_t<typename T::Fields>> : std::true_type {};

// Traits to detect T::methodSpecs, T::fieldSpecs static variables
// T::methodSpecs
template<typename, typename = void>
    struct has_method_specs : std::false_type {};
template<typename T>
    struct has_method_specs<T, std::void_t<decltype(T::methodSpecs)>> : std::true_type {};
// T::fieldSpecs
template<typename, typename = void>
    struct has_field_specs : std::false_type {};
template<typename T>
    struct has_field_specs<T, std::void_t<decltype(T::fieldSpecs)>> : std::true_type {};

template<typename T> T JNI::buildClassSpec(const char * class_name)
{
    static_assert(std::is_standard_layout_v<T>, "buildClassSpec<T>: T must be standard-layout structure");

    T result {};
    // At first, resolve the class
    auto clazz = getClass(class_name);

    // Lookup for methods
    if constexpr (has_methods_struct<T>::value) {
        static_assert(std::is_standard_layout_v<typename T::Methods>, "buildClassSpec<T>: T::Methods must be standard-layout structure");
        static_assert(has_method_specs<T>::value, "buildClassSpec<T>: T must have static member 'methodSpecs'");
        auto methods_base = reinterpret_cast<char*>(&result.methods);
        {
            for (size_t i = 0; i < std::size(T::methodSpecs); ++i) {
                const JniMethodSpec& spec = T::methodSpecs[i];
                switch (spec.type) {
                    case JniMethodType::Constructor: {
                        auto dest = reinterpret_cast<JniInitMethod *>(methods_base + spec.targetOffset);
                        dest->methodId = clazz.findMethod(spec.name, spec.signature);
                        break;
                    }
                    case JniMethodType::Method:
                    case JniMethodType::NonVirtual: {
                        auto dest = reinterpret_cast<JniMethod *>(methods_base + spec.targetOffset);
                        *dest = clazz.findMethod(spec.name, spec.signature);
                        break;
                    }
                    case JniMethodType::Static: {
                        auto dest = reinterpret_cast<JniMethod *>(methods_base + spec.targetOffset);
                        *dest = clazz.findStaticMethod(spec.name, spec.signature);
                        break;
                    }
                }
            }
        }
    }
    // Lookup for fields
    if constexpr (has_fields_struct<T>::value) {
        static_assert(std::is_standard_layout_v<typename T::Fields>, "buildClassSpec<T>: T::Fields must be standard-layout structure");
        static_assert(has_field_specs<T>::value, "buildClassSpec<T>: T must have static member 'fieldSpecs'");
        auto fields_base = reinterpret_cast<char*>(&result.methods);
        {
            for (size_t i = 0; i < std::size(T::fieldSpecs); ++i) {
                const JniFieldSpec& spec = T::fieldSpecs[i];
                auto dest = reinterpret_cast<jfieldID*>(fields_base + spec.targetOffset);
                if (spec.type == JniFieldType::Field) {
                    *dest = clazz.findField(spec.name, spec.signature);
                } else {
                    *dest = clazz.findStaticField(spec.name, spec.signature);
                }
            }
        }
    }
    // So far, so good, make jclass reference global, and update appropriate members in the structure.
    result.classRef = clazz.makeGlobal();

    // Update constructor structures with the global reference
    if (has_methods_struct<T>::value) {
        auto methods_base = reinterpret_cast<char*>(&result.methods);
        for (size_t i = 0; i < std::size(T::methodSpecs); ++i) {
            const JniMethodSpec& spec = T::methodSpecs[i];
            if (spec.type == JniMethodType::Constructor) {
                auto dest = reinterpret_cast<JniInitMethod *>(methods_base + spec.targetOffset);
                dest->classRef = result.classRef;
            }
        }
    }
    // Finally, return the result structure,
    return result;
}

// enums

template<typename T> T JNI::fromJava(const JniCommon::ConstantSetSpec& spec, jint value)
{
    if (spec.values.find(value) == spec.values.end()) {
        throw std::invalid_argument(std::string("Cannot convert Java integer value to enumeration. Class: ") + spec.className);
    }
    return static_cast<T>(value);
}

template<typename T> jint JNI::toJava(const JniCommon::ConstantSetSpec& spec, T value)
{
    auto int_value = static_cast<jint>(value);
    if (spec.values.find(int_value) != spec.values.end()) {
        return int_value;
    }
    throw std::invalid_argument(std::string("Cannot convert enumeration to Java integer. Class: ") + spec.className);
}

template<typename T> T JNI::fromJava(const JniCommon::ConstantRangeSpec& spec, jint value)
{
    if (value >= spec.bottomValue && value <= spec.topValue) {
        return static_cast<T>(value);
    }
    throw std::invalid_argument(std::string("Cannot convert Java integer value to enumeration. Class: ") + spec.className);
}

template<typename T> jint JNI::toJava(const JniCommon::ConstantRangeSpec& spec, T value)
{
    auto int_value = static_cast<jint>(value);
    if (int_value >= spec.bottomValue && int_value <= spec.topValue) {
        return int_value;
    }
    throw std::invalid_argument(std::string("Cannot convert enumeration to Java integer. Class: ") + spec.className);
}

// handle objects

template<typename T> jlong JNI::toHandle(const std::shared_ptr<T>& object, bool release_on_exception)
{
    auto handle = global().objectRegister().registerObject(object);
    if (release_on_exception) {
        _release_on_fail.push_back(handle);
    }
    return handle;
}

template <typename T> jobject JNI::toJava(const JniCommon::NativeHandleClass& spec, const std::shared_ptr<T>& object)
{
    auto& reg = global().objectRegister();
    auto handle = reg.registerObject<T>(object);
    try {
        return createObject(spec.initHandle, handle);
    } catch (...) {
        // Delete registered instance and re-throw exception.
        reg.removeEntry(handle);
        std::rethrow_exception(std::current_exception());
    }
}

template<class T> std::shared_ptr<T> JNI::fromJava(const JniCommon::NativeHandleClass& spec, jobject object)
{
    if (object) {
        auto handle = fromJava(object, spec.classRef).getLong(spec.handle);
        return global().objectRegister().getTypedObject<T>(handle);
    }
    return nullptr;
}

} // namespace cc7::jni
