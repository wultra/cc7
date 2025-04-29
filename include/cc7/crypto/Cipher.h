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

#include <cc7/crypto/Algorithm.h>
#include <cc7/crypto/SymmetricKey.h>

namespace cc7
{
namespace crypto
{

class Cipher : public Algorithm
{
public:
    virtual ByteArray encrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & plaintext) const = 0;
        
    virtual ByteArray decrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & ciphertext) const = 0;
    
    ByteArray encrypt(const SymmetricKey & secret_key, const ByteRange & iv, const ByteRange & plaintext) const
    {
        return encrypt(secret_key.getKeyData(), iv, plaintext);
    }
        
    ByteArray decrypt(const SymmetricKey & secret_key, const ByteRange & iv, const ByteRange & ciphertext) const
    {
        return decrypt(secret_key.getKeyData(), iv, ciphertext);
    }
        
    static std::shared_ptr<Cipher> getInstance(const std::string & algorithm);
};

typedef std::shared_ptr<Cipher> CipherPtr;

} // cc7::crypto
} // cc7
