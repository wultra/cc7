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

struct PBKDF2Spec
{
    std::string name;
    
    std::string ossl_alg;
    std::string ossl_md;
    
    static const PBKDF2Spec * specForAlgorithm(const std::string & algorithm);
};


class PBKDF2 : public KeyDerivation
{
public:
    // KeyDerivation
    cc7::ByteArray deriveKeyBytes(const ByteRange & key_material, const ParameterList & parameters) const override;
    
    // Alforithm
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

    static KeyDerivationPtr getInstance(const std::string & alg_name);

    PBKDF2(const PBKDF2Spec * spec) : _spec(spec), _out_size(0), _iterations(0) {}

private:

    const PBKDF2Spec * _spec;
    
    size_t _out_size;
    size_t _iterations;
};

} // cc7::crypto
} // cc7

