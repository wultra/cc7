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

#include <cc7/jni/JniObjectRegister.h>
#include <cc7/jni/JniException.h>

namespace cc7::jni {

#define LOCK_GUARD() std::lock_guard<std::mutex> _lock_guard(_lock)

JniObjectRegister::ObjID JniObjectRegister::registerObject(const BaseObjectPtr& ptr)
{
    LOCK_GUARD();
    if (ptr == nullptr) {
        throw std::invalid_argument("Null pointer cannot be registered");
    }
    
    auto object_id = ++_next_id;
    _register.insert({ object_id, ptr });
    return object_id;
}

void JniObjectRegister::removeObject(ObjID object_id)
{
    LOCK_GUARD();
    auto it = _register.find(object_id);
    if (it == _register.end()) {
        throw JniBadHandleException("Native object not found. ID = " + std::to_string(object_id));
    }
    _register.erase(it);
}

void JniObjectRegister::removeObjects(const std::vector<ObjID>& object_ids)
{
    LOCK_GUARD();
    auto failed_id = NULL_ID;
    for (auto object_id : object_ids) {
        auto it = _register.find(object_id);
        if (it != _register.end()) {
            _register.erase(it);
        } else {
            failed_id = object_id;
        }
    }
    if (failed_id != NULL_ID) {
        throw JniBadHandleException("Native object not found. ID = " + std::to_string(failed_id));
    }
}

BaseObjectPtr JniObjectRegister::getObject(ObjID object_id) const
{
    LOCK_GUARD();
    auto it = _register.find(object_id);
    if (it == _register.end()) {
        throw JniBadHandleException("Native object not found. ID = " + std::to_string(object_id));
    }
    return it->second;
}

bool JniObjectRegister::containsObject(ObjID object_id) const noexcept
{
    LOCK_GUARD();
    return _register.find(object_id) != _register.end();
}

} // namespace cc7::jni
