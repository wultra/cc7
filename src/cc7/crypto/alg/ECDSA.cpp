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

#include "ECDSA.h"

namespace cc7::crypto {

// MARK: - ECDSASpec structure

const ECDSASpec ECDSASpec::ECDSA_SHA_256  = { "ECDSA-SHA-256"  , EVP_sha256(),   &ECCurveSpec::P_256 };
const ECDSASpec ECDSASpec::ECDSA_SHA_384  = { "ECDSA-SHA-384"  , EVP_sha384(),   &ECCurveSpec::P_384 };
const ECDSASpec ECDSASpec::ECDSA_SHA_512  = { "ECDSA-SHA-512"  , EVP_sha512(),   &ECCurveSpec::P_521 };
const ECDSASpec ECDSASpec::ECDSA_SHA3_256 = { "ECDSA-SHA3-256" , EVP_sha3_256(), &ECCurveSpec::P_256 };
const ECDSASpec ECDSASpec::ECDSA_SHA3_384 = { "ECDSA-SHA3-384" , EVP_sha3_384(), &ECCurveSpec::P_384 };
const ECDSASpec ECDSASpec::ECDSA_SHA3_512 = { "ECDSA-SHA3-512" , EVP_sha3_512(), &ECCurveSpec::P_521 };

const ECDSASpec * ECDSASpec::altorithmToSpec(const std::string &algorithm)
{
    static std::vector<const ECDSASpec*> spec_list {
        &ECDSA_SHA3_256, &ECDSA_SHA3_384, &ECDSA_SHA3_512,
        &ECDSA_SHA_256,  &ECDSA_SHA_384,  &ECDSA_SHA_512,
    };
    for (auto spec : spec_list) {
        if (spec->name == algorithm) {
            return spec;
        }
    }
    return nullptr;
}

// MARK: - ECDSA implementation

std::shared_ptr<ECDSA> ECDSA::getInstance(const std::string & algorithm)
{
    auto spec = ECDSASpec::altorithmToSpec(algorithm);
    if (!spec) {
        return nullptr;
    }
    return std::shared_ptr<ECDSA>(new ECDSA(spec));
}

// Signature interface

ByteArray ECDSA::sign(const PrivateKey & private_key, const ByteRange & data, const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    
    const auto& ec_key = checkECPrivateKey(private_key, _spec->curve, true);
    const auto& ll_key = ec_key.getEvpKey();
    
    auto ctx = EVPMDContext::empty();
    if (!ctx.isValid()) {
        throw CryptoException("Failed to create context for data signing");
    }
    if (EVP_DigestSignInit(ctx, nullptr, _spec->md, nullptr, ll_key) != 1) {
        throw CryptoException("Failed to initialize context for data signing");
    }
    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
        throw CryptoException("Failed to compute hash from data");
    }
    cc7::ByteArray signature;
    size_t sig_length = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_length) != 1) {
        throw CryptoException("Failed to estimate length of the signature");
    }
    signature.resize(sig_length);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_length) != 1) {
        throw CryptoException("Failed to compute signature");
    }
    // Final signature length may differ to estimated
    signature.resize(sig_length);
    return signature;
}

bool ECDSA::verify(const PublicKey & public_key, const ByteRange & signature, const ByteRange & data, const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    
    const auto& ec_key = checkECPublicKey(public_key, _spec->curve);
    const auto& ll_key = ec_key.getEvpKey();
    
    auto ctx = EVPMDContext::empty();
    if (!ctx.isValid()) {
        throw CryptoException("Failed to create context for signature verification");
    }
    if (EVP_DigestVerifyInit(ctx, nullptr, _spec->md, nullptr, ll_key) != 1) {
        throw CryptoException("Failed to initialize context for signature verification");
    }
    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) != 1) {
        throw CryptoException("Failed to compute hash from data");
    }
    auto r = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    return r == 1;
}

// Algorithm interface

const std::string & ECDSA::getAlgorithmName() const
{
    return _spec->name;
}

void ECDSA::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter ECDSA::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

} // namespace cc7::crypto

