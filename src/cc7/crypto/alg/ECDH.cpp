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

#include "ECDH.h"

namespace cc7
{
namespace crypto
{

static const std::string ECDH_ALG("ECDH");

std::shared_ptr<ECDH> ECDH::getInstance(const std::string & algorithm, KeyDerivationPtr kdf_function)
{
    if (algorithm == ECDH_ALG) {
        if (kdf_function == nullptr) {
            throw std::invalid_argument("KeyDerivation function must be specified");
        }
        return std::shared_ptr<ECDH>(new ECDH(kdf_function));
    }
    return nullptr;
}

// KeyAgreement interface

SymmetricKeyPtr ECDH::phase(const PrivateKey & private_key, const PublicKey & peer_key) const
{
    const auto& ec_private_key = checkECPrivateKey(private_key, nullptr, false);
    const auto& ec_peer_key = checkECPublicKey(peer_key, nullptr);
    if (ec_private_key.curveSpec() != ec_peer_key.curveSpec()) {
        throw std::invalid_argument("Private and peer key type doesn't match");
    }
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_pkey(ossl_ctx(), ec_private_key.getEvpKey(), NULL));
    if (!ctx.isValid() || EVP_PKEY_derive_init(ctx) <= 0) {
        throw std::domain_error("Failed to initialize ECDH context");
    }
    if (EVP_PKEY_derive_set_peer_ex(ctx, ec_peer_key.getEvpKey(), 1) <= 0) {
        throw std::domain_error("Failed to set peer key to ECDH context");
    }
    ByteArray raw_secret;
    size_t secret_size = 0;
    if (EVP_PKEY_derive(ctx, NULL, &secret_size) <= 0) {
        throw std::domain_error("Failed to determine size of ECDH shared secret");
    }
    raw_secret.resize(secret_size);
    if (EVP_PKEY_derive(ctx, raw_secret.data(), &secret_size) <= 0) {
        throw std::domain_error("Failed to compute ECDH shared secret");
    }
    return _key_derivation->derive(raw_secret);
}

// Algorithm interface

const std::string & ECDH::getAlgorithmName() const
{
    return ECDH_ALG;
}

void ECDH::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case KEY_AGREEMENT_PARAM_KDF: {
            auto kdf_function = std::dynamic_pointer_cast<KeyDerivation>(value.asObject());
            if (kdf_function == nullptr) {
                throw std::invalid_argument("Object must be type of KeyDerivation");
            }
            _key_derivation = kdf_function;
            break;
        }
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter ECDH::getParameter(int param_id) const
{
    switch (param_id) {
        case KEY_AGREEMENT_PARAM_KDF:
            return Parameter::from(_key_derivation);
            
        default:
            throwUnsupportedParam(param_id);
    }
}
    
} // cc7::crypto
} // cc7
