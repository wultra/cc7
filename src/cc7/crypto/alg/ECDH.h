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

#include <cc7/crypto/KeyAgreement.h>
#include "ECKeyPair.h"

namespace cc7
{
namespace crypto
{

class ECDH : public KeyAgreement
{
public:
    // KeyAgreement interface
    SymmetricKeyPtr phase(const PrivateKey & private_key, const PublicKey & peer_key, const ParameterList & parameters) const override;
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;
    
    static std::shared_ptr<ECDH> getInstance(const std::string & algorithm, KeyDerivationPtr kdf_function);
    
private:
    
    KeyDerivationPtr _key_derivation;
    
    ECDH(KeyDerivationPtr kdf) : _key_derivation(kdf) {}
};
    
} // cc7::crypto
} // cc7
