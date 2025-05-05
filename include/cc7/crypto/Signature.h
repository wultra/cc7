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
#include <cc7/crypto/KeyPair.h>

namespace cc7
{
namespace crypto
{

class Signature : public Algorithm
{
public:
    
    virtual ByteArray sign(const PrivateKey & private_key,
                           const ByteRange & data,
                           const ParameterList & parameters = {}) const = 0;
    
    virtual bool verify(const PublicKey & public_key,
                        const ByteRange & signature,
                        const ByteRange & data,
                        const ParameterList & parameters = {}) const = 0;
    
    static std::shared_ptr<Signature> getInstance(const std::string & algorithm);
};

typedef std::shared_ptr<Signature> SignaturePtr;

} // cc7::crypto
} // cc7
