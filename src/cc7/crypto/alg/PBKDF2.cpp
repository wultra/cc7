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

#include "PBKDF2.h"

namespace cc7
{
namespace crypto
{

// MARK: PBKDF2Spec implementation

const PBKDF2Spec * PBKDF2Spec::specForAlgorithm(const std::string & algorithm)
{
    
    static const std::vector<PBKDF2Spec> spec_list {
        { "PBKDF2-HMAC-SHA-256",  OSSL_KDF_NAME_PBKDF2, "SHA-256"  },
        { "PBKDF2-HMAC-SHA-384",  OSSL_KDF_NAME_PBKDF2, "SHA-384"  },
        { "PBKDF2-HMAC-SHA-512",  OSSL_KDF_NAME_PBKDF2, "SHA-512"  },
        { "PBKDF2-HMAC-SHA3-256", OSSL_KDF_NAME_PBKDF2, "SHA3-256" },
        { "PBKDF2-HMAC-SHA3-384", OSSL_KDF_NAME_PBKDF2, "SHA3-384" },
        { "PBKDF2-HMAC-SHA3-512", OSSL_KDF_NAME_PBKDF2, "SHA3-512" },
        { "PBKDF2-HMAC-SHA-1",    OSSL_KDF_NAME_PBKDF2, "SHA-1"    }
    };
    for (const auto & spec : spec_list) {
        if (spec.name == algorithm) {
            return &spec;
        }
    }
    return nullptr;
}

// MARK: PBKDF2 implementation

cc7::ByteArray PBKDF2::deriveKeyBytes(const ByteRange & key_material, const ParameterList & parameters) const
{
    size_t out_size = _out_size;
    size_t in_iterations = _iterations;
    ByteRange in_salt;
    
    auto param_ctx = parameters.beginParameterProcessing();
    parameters.getSize(KDF_PARAM_ITERATIONS, param_ctx, in_iterations);
    parameters.getBytes(KDF_PARAM_SALT, param_ctx, in_salt);
    parameters.getSize(KDF_PARAM_KEY_SIZE, param_ctx, out_size);
    parameters.consumeParam(KDF_PARAM_KEY_TYPE, param_ctx);
    parameters.endParameterProcessing(param_ctx);
    
    if (!out_size) {
        throw std::invalid_argument("Output size for KDF not specified");
    }
    if (in_salt.empty()) {
        throw std::invalid_argument("Salt is empty");
    }
    if (!in_iterations) {
        throw std::invalid_argument("Number of iterations not specified");
    }
    
    auto builder = OSSLParamBuilder::empty();
    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_KDF_PARAM_DIGEST, _spec->ossl_md.c_str(), 0);
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_KDF_PARAM_PASSWORD, key_material.data(), key_material.size());
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_KDF_PARAM_SALT, in_salt.data(), in_salt.size());
    OSSL_PARAM_BLD_push_int(builder, OSSL_KDF_PARAM_PKCS5, 1);
    OSSL_PARAM_BLD_push_int(builder, OSSL_KDF_PARAM_ITER,  (int)in_iterations);
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
    
    auto kdf = EVPKdf::take(EVP_KDF_fetch(ossl_ctx(), _spec->ossl_alg.c_str(), nullptr));
    auto ctx = EVPKdfContext::take(EVP_KDF_CTX_new(kdf));
    if (!ctx.isValid() || !kdf.isValid()) {
        throw std::domain_error("Failed to initialize KDF and context");
    }
    ByteArray out(out_size, 0);
    if (EVP_KDF_derive(ctx, out.data(), out_size, params) != 1) {
        throw std::domain_error("Failed to derive secret key");
    }
    return out;
}

const std::string & PBKDF2::getAlgorithmName() const
{
    return _spec->name;
}

void PBKDF2::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case KDF_PARAM_KEY_SIZE:
            _out_size = value.asSize();
            break;
        case KDF_PARAM_ITERATIONS:
            _iterations = value.asInt();
            break;
            
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter PBKDF2::getParameter(int param_id) const
{
    switch (param_id) {
        case KDF_PARAM_KEY_SIZE:
            return Parameter::take(_out_size);
        case KDF_PARAM_ITERATIONS:
            return Parameter::take(_iterations);
            
        default:
            throwUnsupportedParam(param_id);
    }
}

KeyDerivationPtr PBKDF2::getInstance(const std::string & alg_name)
{
    auto spec = PBKDF2Spec::specForAlgorithm(alg_name);
    if (!spec) {
        return nullptr;
    }
    return std::make_shared<PBKDF2>(spec);
}


} // cc7::crypto
} // cc7
