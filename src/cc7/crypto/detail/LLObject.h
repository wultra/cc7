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

namespace cc7
{
namespace crypto
{

/**
 The `TLLRefObject` template helper class is responsible for capturing and managing lifetime of
 low-level objects from OpenSSL. This variant of template is designed to manage reference-counter objects,
 such as `EVP_PKEY` structure.
 
 The template class implements casting operator to `T*` and therefore can be easily used as
 a parameter to functions, which requires pointet to type T.
 */
template <typename T, T* (*CreateFunc)(), int (*RetainFunc)(T*), void (*ReleaseFunc)(T*)> class TLLRefObject {
public:
    
    /// Plain constructor creates an invalid object.
    TLLRefObject() : _ll_object(nullptr) {}
    
    // Copy constructor - retains ll object
    TLLRefObject(const TLLRefObject & other) {
        _ll_object = other._ll_object;
        if (_ll_object) {
            RetainFunc(_ll_object);
        }
    }
    
    // Move constructor - move ptr only.
    TLLRefObject(TLLRefObject && other) {
        _ll_object = other._ll_object;
        other._ll_object = nullptr;
    }
    
    // Destructor
    ~TLLRefObject() {
        destroy();
    }
    
    // Copy Assignment
    TLLRefObject& operator=(const TLLRefObject& other) {
        if (this != &other) {
            assign(other._ll_object);
        }
        return *this;
    }
    
    // Move Assignment
    TLLRefObject& operator=(TLLRefObject&& other) {
        if (this != &other) {
            if (_ll_object != other._ll_object) {
                destroy();
            }
            _ll_object = other._ll_object;
            other._ll_object = nullptr;
        }
        return *this;
    }
    
    // Take ownership of provided object. The reference count is not increased.
    static TLLRefObject take(T * ll_object) {
        return TLLRefObject(ll_object, false);
    }

    // Keep provided object and increase the reference count.
    static TLLRefObject ref(T * ll_object) {
        return TLLRefObject(ll_object, true);
    }
            
    // Create an empty object. If CreateFunc template parameter is not provided, then
    // it's equal to ::invalid().
    static TLLRefObject empty() {
        return TLLRefObject(CreateFunc ? CreateFunc() : nullptr, false);
    }
    
    // Return low level object captured in this object.
    T * object() const {
        return _ll_object;
    }
    
    // Cast TLLObject to T pointer to use in low-level functions automatically.
    operator T * () const {
        return _ll_object;
    }
    
    // Return true if object contains valid low-level object.
    bool isValid() const {
        return _ll_object != nullptr;
    }
    
    // Assign low level object
    void assign(T * ll_object) {
        if (_ll_object != ll_object) {
            destroy();
            _ll_object = ll_object;
            if (_ll_object) {
                RetainFunc(_ll_object);
            }
        }
    }
    
    // Destroy low level object.
    void destroy() {
        if (_ll_object) {
            ReleaseFunc(_ll_object);
            _ll_object = nullptr;
        }
    }
            
protected:
    
    TLLRefObject(T * ll_object, bool retain) : _ll_object(ll_object) {
        if (_ll_object && retain) {
            RetainFunc(_ll_object);
        }
    }
    
private:
    
    T * _ll_object;
};

/**
 The `TLLObject` template helper class is responsible for capturing and managing lifetime of
 low-level objects from OpenSSL. This variant of template is suited for non-reference counter
 objects, such as BIGNUM.
 
 The template class implements casting operator to `T*` and therefore can be easily used as
 a parameter to functions, which requires pointet to type T.
 */
template <typename T, T* (*CreateFunc)(), void (*ReleaseFunc)(T*)> class TLLObject {
public:
    
    // Move constructor - move ptr only.
    TLLObject(TLLObject && other) {
        _ll_object = other._ll_object;
        other._ll_object = nullptr;
    }
    
    // Move Assignment
    TLLObject& operator=(TLLObject&& other) {
        if (this != &other) {
            if (_ll_object != other._ll_object) {
                destroy();
            }
            _ll_object = other._ll_object;
            other._ll_object = nullptr;
        }
        return *this;
    }

    // Take ownership of provided object. The low level object will be destroyed in object's
    // constructor.
    static TLLObject take(T * ll_object) {
        return TLLObject(ll_object);
    }
            
    // Create an empty object. If CreateFunc template parameter is not provided, then
    // the created object is invalid.
    static TLLObject empty() {
        return TLLObject(CreateFunc ? CreateFunc() : nullptr);
    }
        
    // Destructor
    ~TLLObject() {
        destroy();
    }
    
    // Return low level object captured in this object.
    T * object() const {
        return _ll_object;
    }
    
    // Cast TLLObject to T pointer to use in low-level functions automatically.
    operator T * () const {
        return _ll_object;
    }
    
    // Return true if object contains valid low-level object.
    bool isValid() const {
        return _ll_object != nullptr;
    }
        
    void destroy() {
        if (_ll_object) {
            ReleaseFunc(_ll_object);
            _ll_object = nullptr;
        }
    }
    
    void assign(T * ll_object) {
        if (_ll_object != ll_object) {
            destroy();
        }
        _ll_object = ll_object;
    }
    
protected:
    
    TLLObject(T * ll_object) : _ll_object(ll_object) {
    }

private:
    
    T * _ll_object;
};

/**
 The `TLLMemory` template allows to capture memory allocated elsewhere and guarantess that
 it's released with the predefined function.
 */
template <typename T, void (*ReleaseFunc)(T*)> class TLLMemory {
public:
    TLLMemory() : _ptr(nullptr) {}
    
    ~TLLMemory() {
        destroy();
    }
    
    // Move constructor - move ptr only.
    TLLMemory(TLLMemory && other) {
        _ptr = other._ptr;
        other._ptr = nullptr;
    }
    
    // Move Assignment
    TLLMemory& operator=(TLLMemory&& other) {
        if (this != &other) {
            if (_ptr != other._ptr) {
                destroy();
            }
            _ptr = other._ptr;
            other._ptr = nullptr;
        }
        return *this;
    }

    // Take ownership of provided pointer.
    static TLLMemory take(T * ptr) {
        return TLLMemory(ptr);
    }
    
    void destroy() {
        if (_ptr) {
            ReleaseFunc(_ptr);
            _ptr = nullptr;
        }
    }
    
    // Return pointer captured in this object.
    T * ptr() const {
        return _ptr;
    }
    
    // Return reference to pointer captured in this object. If pointer is already allocated, then
    // captured memory is destroyed.
    T ** ref() {
        destroy();
        return &_ptr;
    }
    
    // Cast TLLMemory to T pointer to use in low-level functions automatically.
    operator T * () const {
        return _ptr;
    }
    
    // Return true if object contains valid pointer.
    bool isValid() const {
        return _ptr != nullptr;
    }
    
private:
    
    TLLMemory(T * ptr) : _ptr(ptr) {}
    
    T * _ptr;
};

/**
 The `TWrapIntToVoid` template function wraps function returning int value into void function. The value
 returned from the original function is ignored.
 */
template <typename T, int (*IntWrapped)(T*)> void TWrapIntToVoid(T * ll_object) {
    IntWrapped(ll_object);
}

/**
 The `TFuncWithParam1` template function allows to call parametrized function, returning `T*` witch
 constant parameter.
 */
template <typename T, typename U, T* (*Parametrized)(U), U value> T * TFuncWithParam1() {
    return Parametrized(value);
}

} // cc7::crypto
} // cc7
