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
#include <unordered_map>
#include <mutex>

namespace cc7::jni {

/// The `JniObjectRegister` class manages std::shared_ptr<T> references in a centralized registry.
class JniObjectRegister
{
public:
    /// Type used for object identifiers.
    typedef int64_t ObjID;

    /// A constant representing a null identifier.
    static const ObjID NULL_ID = 0L;

    /// Base structure stored in the register.
    struct Entry
    {
        virtual ~Entry() = default;
        virtual bool isNull() { return true; }
    };

    typedef std::shared_ptr<Entry> EntryRef;

    /// Type safe structure for storing shared_ptr<T> pointers in the register.
    template <typename T> struct TypedEntry : public Entry
    {
        TypedEntry(const std::shared_ptr<T>& ptr) : ref(ptr) {}
        bool isNull() override { return ref == nullptr; }
        std::shared_ptr<T> ref;
    };

    /// Register object entry and return a unique identifier associated with it.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - entry: Shared pointer to the entry. Must not be null.
    /// - Returns: Identifier assigned to this object instance.
    /// - Throws:
    ///   - `std::invalid_argument` if `ptr` is `nullptr` or `entry->isNull()` is false.
    ObjID registerEntry(const EntryRef& entry);

    /// Check whether an object with the given identifier is currently registered.
    ///
    /// This method is primarily intended for debugging or diagnostic purposes.
    /// In multi-threaded scenarios, you must ensure appropriate external
    /// synchronization if you perform additional operations based on the result
    /// of this call. The internal mutex only protects individual operations on
    /// the registry and is not sufficient to guarantee correctness of more
    /// complex sequences of operations.
    ///
    /// - Parameters:
    ///   - object_id: Object identifier.
    /// - Returns: `true` if an object with the given identifier is registered, `false` otherwise.
    /// - Throws: Never.
    bool containsEntry(ObjID object_id) const noexcept;

    /// Retrieve a pointer to a registered object.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - object_id: Object identifier.
    /// - Returns: Shared pointer to the registered object.
    /// - Throws:
    ///   - `jni::JniBadHandleException` if no object with the given `object_id` exists in the registry.
    EntryRef getEntry(ObjID object_id) const;

    /// Remove a previously registered object.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - object_id: Object identifier.
    /// - Throws:
    ///   - `jni::JniBadHandleException` if no object with the given `object_id` exists in the registry.
    void removeEntry(ObjID object_id);

    /// Remove multiple previously registered object.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - object_ids: Object identifiers.
    /// - Throws:
    ///   - `jni::JniBadHandleException` if array contains object that doesn't exists in the registry.
    void removeEntries(const std::vector<ObjID>& object_ids);

    // Typed objects

    /// Register a std::shared_ptr<T> typed pointer and return a unique identifier associated with it.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - ptr: Shared pointer to the object to register. Must not be null.
    /// - Returns: Identifier assigned to this object instance.
    /// - Throws:
    ///   - `std::invalid_argument` if `ptr` is `nullptr`.
    template <typename T> ObjID registerObject(const std::shared_ptr<T>& ptr)
    {
        return registerEntry(std::make_shared<TypedEntry<T>>(ptr));
    }

    /// Retrieve a typed pointer to a registered object.
    ///
    /// This function performs a `std::dynamic_pointer_cast` to the requested type `T`.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - object_id: Object identifier.
    /// - Returns: Shared pointer to the registered object cast to `std::shared_ptr<T>`.
    /// - Throws:
    ///   - `jni::JniBadHandleException` if no object with the given `object_id` exists in the registry.
    ///   - `std::invalid_argument` if the object exists but cannot be cast to `T`.
    template<typename T> std::shared_ptr<T> getTypedObject(ObjID object_id) const
    {
        auto entry = getEntry(object_id);
        auto typed = std::dynamic_pointer_cast<TypedEntry<T>>(entry);
        if (typed == nullptr) {
            throw std::invalid_argument("Object stored in the register has different type. ID = " + std::to_string(object_id));
        }
        return typed->ref;
    }

private:

    typedef std::unordered_map<ObjID, EntryRef> ObjMap;

    mutable std::mutex  _lock;
    ObjMap              _register;
    ObjID               _next_id = 0;
};

} // namespace cc7::jni
