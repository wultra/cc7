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

#include "X963KDF.h"

namespace cc7
{
namespace crypto
{

// MARK: X963KDFSpec implementation

const X963KDFSpec * X963KDFSpec::specForAlgorithm(const std::string & algorithm)
{
    static const std::vector<X963KDFSpec> spec_list {
        { "X963KDF-SHA-256", OSSL_KDF_NAME_X963KDF, "SHA-256", 32 }
    };
    for (const auto & spec : spec_list) {
        if (spec.name == algorithm) {
            return &spec;
        }
    }
    return nullptr;
}

// MARK: X963KDF implementation

cc7::ByteArray X963KDF::deriveKeyBytes(const ByteRange & key_material, const ParameterList & parameters) const
{
    size_t out_size = _out_size;
    ByteArray in_info;
    auto param_ctx = parameters.beginParameterProcessing();
    parameters.getSize(PARAM_OUT_KEY_SIZE, param_ctx, out_size);
    parameters.getBytes(KDF_PARAM_INFO, param_ctx, in_info);
    parameters.consumeParam(PARAM_OUT_KEY_TYPE, param_ctx);
    parameters.endParameterProcessing(param_ctx);
    if (!out_size) {
        throw std::invalid_argument("Output size for KDF not specified");
    }
    
    auto builder = OSSLParamBuilder::empty();
    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_KDF_PARAM_DIGEST, _spec->ossl_md.c_str(), 0);
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_KDF_PARAM_KEY, key_material.data(), key_material.size());
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_KDF_PARAM_INFO, in_info.data(), in_info.size());
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
    
    auto kdf = EVPKdf::take(EVP_KDF_fetch(ossl_ctx(), _spec->ossl_alg.c_str(), nullptr));
    auto ctx = EVPKdfContext::take(EVP_KDF_CTX_new(kdf));
    if (!ctx.isValid() || !kdf.isValid()) {
        throw std::domain_error("Failed to initialize KDF and context");
    }
    ByteArray out(out_size, 0);
    if (EVP_KDF_derive(ctx, out.data(), out.size(), params) != 1) {
        throw std::domain_error("Failed to derive secret key");
    }
    return out;
}

const std::string & X963KDF::getAlgorithmName() const
{
    return _spec->name;
}

void X963KDF::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case PARAM_OUT_KEY_SIZE:
            _out_size = value.asSize();
            break;
            
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter X963KDF::getParameter(int param_id) const
{
    switch (param_id) {
        case PARAM_OUT_KEY_SIZE:
            return Parameter::from(_out_size);
            
        default:
            throwUnsupportedParam(param_id);
    }
}

KeyDerivationPtr X963KDF::getInstance(const std::string & alg_name)
{
    auto spec = X963KDFSpec::specForAlgorithm(alg_name);
    if (!spec) {
        return nullptr;
    }
    return std::make_shared<X963KDF>(spec);
}


} // cc7::crypto
} // cc7
