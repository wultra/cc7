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

#include <cc7/crypto/SymmetricKey.h>
#include <cc7/crypto/Algorithm.h>

namespace cc7 {
namespace crypto {

class AEAD : public Algorithm
{
public:    
    virtual ByteArray seal(const ByteRange & key,
                           const ByteRange & nonce,
                           const ByteRange & associated_data,
                           const ByteRange & plaintext,
                           const ParameterList & params = {}) const = 0;
    
    virtual ByteArray open(const ByteRange & key,
                           const ByteRange & associated_data,
                           const ByteRange & ciphertext,
                           const ParameterList & params = {}) const = 0;
    
    ByteArray seal(const SymmetricKey & key,
                   const ByteRange & nonce,
                   const ByteRange & associated_data,
                   const ByteRange & plaintext,
                   const ParameterList & params = {}) const;
    
    ByteArray open(const SymmetricKey & key,
                   const ByteRange & associated_data,
                   const ByteRange & ciphertext,
                   const ParameterList & params = {}) const;
    
    static std::shared_ptr<AEAD> getInstance(const std::string & algorithm);
};

typedef std::shared_ptr<AEAD> AEADPtr;

} // cc7::crypto
} // cc7
