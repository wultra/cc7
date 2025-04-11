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

#include <cc7/crypto/KeyEncapsulation.h>
#include "../CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

struct MLKEMSpec
{
    std::string name;
    
    static const MLKEMSpec * specForAlgorithm(const std::string & algorithm);
    
    static const MLKEMSpec ML_KEM_512;
    static const MLKEMSpec ML_KEM_768;
    static const MLKEMSpec ML_KEM_1024;
};

class MLKEM : public KeyEncapsulation
{
public:
    
    static std::shared_ptr<MLKEM> getInstance(const std::string & algorithm);
    
    // KeyEncapsulation interface
    
    virtual KeyPairPtr generate() const;
    virtual std::pair<ByteArray, SymmetricKeyPtr> encapsulate(const PublicKey & encapsulation_key) const;
    virtual SymmetricKeyPtr decapsulate(const PrivateKey & decapsulation_key, const ByteArray & encapsulated_key) const;
    
private:
    
    MLKEM(const MLKEMSpec * spec) : _spec(spec) {}
    
    const MLKEMSpec * _spec;
};

} // cc7::crypto
} // cc7
