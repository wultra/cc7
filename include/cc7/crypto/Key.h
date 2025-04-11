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
#include <cc7/crypto/Constants.h>
#include <cc7/crypto/Parameter.h>
#include <cc7/crypto/BaseObject.h>

namespace cc7
{
namespace crypto
{

class Key : public BaseObject
{
public:
    
    virtual const std::string & getKeyType() const = 0;
            
    virtual void importKey(const ByteRange & key_data, const std::string & format = KEY_FORMAT_DEFAULT) = 0;
    
    virtual ByteArray exportKey(const std::string & format = KEY_FORMAT_DEFAULT) const = 0;
    
    virtual std::shared_ptr<Key> duplicate() const = 0;
    
    virtual Parameter getKeyParameter(int param_id) const = 0;
    
    std::string exportKeyToBase64(const std::string & format = KEY_FORMAT_DEFAULT) const;
    
    void importKeyFromBase64(const std::string & base64Key, const std::string & format = KEY_FORMAT_DEFAULT);
};

typedef std::shared_ptr<Key> KeyPtr;

} // cc7::crypto
} // cc7
