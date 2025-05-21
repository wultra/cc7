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

#include <cc7/crypto/Signature.h>
#include "ECKeyPair.h"

namespace cc7 {
namespace crypto {

struct ECDSASpec
{
    std::string name;
    const EVP_MD * md;
    const ECCurveSpec * curve;
    
    static const ECDSASpec ECDSA_SHA_256;
    static const ECDSASpec ECDSA_SHA_384;
    static const ECDSASpec ECDSA_SHA_512;
    static const ECDSASpec ECDSA_SHA3_256;
    static const ECDSASpec ECDSA_SHA3_384;
    static const ECDSASpec ECDSA_SHA3_512;
    
    static const ECDSASpec * altorithmToSpec(const std::string & algorithm);
};

class ECDSA : public Signature
{
public:
    // Signature interface
    ByteArray sign(const PrivateKey & private_key, const ByteRange & data, const ParameterList & parameters) const override;
    bool verify(const PublicKey & public_key, const ByteRange & signature, const ByteRange & data, const ParameterList & parameters) const override;
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

    
    static std::shared_ptr<ECDSA> getInstance(const std::string & algorithm);
    
private:
    
    ECDSA(const ECDSASpec * spec) : _spec(spec) {}
    
    const ECDSASpec * _spec;
};
    
} // cc7::crypto
} // cc7
