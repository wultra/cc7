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

#include <cc7/crypto/KeyDerivation.h>
#include "../CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

class NullKDF : public KeyDerivation
{
public:
    // KeyDerivation interface
    virtual cc7::ByteArray deriveKeyBytes(const ByteRange & key_material, const ParameterList & parameters) const;
    
    // Algorithm interface
    
    virtual const std::string & getAlgorithmName() const;
    virtual void setParameter(int param_id, const Parameter & value);
    virtual Parameter getParameter(int param_id) const;
    
    static const std::string NULL_KDF;
    
    NullKDF() : _out_key_size(0) {}
    
private:
    std::string _out_key_type;
    size_t      _out_key_size;
};

} // cc7::crypto
} // cc7
