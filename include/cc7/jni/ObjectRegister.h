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

#include <cc7/BaseObject.h>
#include <vector>
#include <map>
#include <mutex>

namespace cc7 {
namespace jni {

/// The `ObjectRegister` class manages `BaseObject` instances in a centralized registry.
class ObjectRegister
{
public:
    /// Type used for object identifiers.
    typedef int64_t ObjID;

    /// Register an object and return a unique identifier associated with it.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - ptr: Shared pointer to the object to register. Must not be null.
    /// - Returns: Identifier assigned to this object instance.
    /// - Throws:
    ///   - `std::invalid_argument` if `ptr` is `nullptr`.
    ObjID registerObject(const BaseObjectPtr& ptr);

    /// Remove a previously registered object.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - object_id: Object identifier.
    /// - Throws:
    ///   - `std::invalid_argument` if no object with the given `object_id` exists in the registry.
    void removeObject(ObjID object_id);

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
    bool containsObject(ObjID object_id) const noexcept;

    /// Retrieve a pointer to a registered object.
    ///
    /// Thread-safety: This function is thread-safe.
    ///
    /// - Parameters:
    ///   - object_id: Object identifier.
    /// - Returns: Shared pointer to the registered object.
    /// - Throws:
    ///   - `std::invalid_argument` if no object with the given `object_id` exists in the registry.
    BaseObjectPtr getObject(ObjID object_id) const;

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
    ///   - `std::invalid_argument` if no object with the given `object_id` exists in the registry.
    ///   - `std::invalid_argument` if the object exists but cannot be cast to `T`.
    template<typename T> std::shared_ptr<T> getTypedObject(ObjID object_id) const
    {
        auto typed = std::dynamic_pointer_cast<T>(getObject(object_id));
        if (typed == nullptr) {
            throw std::invalid_argument("Object stored in the register has different type. ID = " + std::to_string(object_id));
        }
        return typed;
    }

    /// Get a reference to the global registry instance.
    ///
    /// This function returns a singleton `ObjectRegister` that can be used as a process-wide registry.
    ///
    /// Thread-safety: The construction of the global instance is thread-safe, and all subsequent calls are thread-safe.
    static ObjectRegister& global() noexcept;

private:
    
    typedef std::map<ObjID, BaseObjectPtr> ObjMap;

    mutable std::mutex  _lock;
    ObjMap              _register;
    ObjID               _next_id = 0;
};

} // namespace jni
} // namespace cc7