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

#include "MACBase.h"

namespace cc7 {
namespace crypto {

// MARK: MAC interface

ByteArray MACBase::token(const ByteRange & key, const ByteRange & data, const ParameterList & parameters) const
{
    auto ctx = EVPMacContext::take(EVP_MAC_CTX_new(_mac));

    if (!ctx.isValid()) {
        throw CryptoException("Failed to create MAC context");
    }
    MACBaseParams p {
        &parameters,
        parameters.beginParameterProcessing(),
        OSSLParamBuilder::empty(),
        _out_len
    };
    if (!p.builder.isValid() || !prepareParams(p)) {
        throw CryptoException("Failed to prepare parameters for MAC");
    }
    parameters.endParameterProcessing(p.ctx);
    
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(p.builder));

    if (!EVP_MAC_init(ctx, key.data(), key.size(), params)) {
        throw CryptoException("Failed to init MAC context");
    }
    if (!EVP_MAC_update(ctx, data.data(), data.size())) {
        throw CryptoException("MAC update failed");
    }
    // Allocate output buffer, depending on truncate mode. If truncate is enabled, then use the default size,
    // otherwise use the requested size.
    cc7::ByteArray out(_spec->truncate_mode ? _spec->mac_size : p.out_len);
    size_t out_length;
    if (!EVP_MAC_final(ctx, out.data(), &out_length, out.size())) {
        throw CryptoException("MAC final failed");
    }
    if (_spec->truncate_mode && p.out_len != _spec->mac_size) {
        // truncate output to requested size
        out.resize(p.out_len);
    }
    return out;
}

bool MACBase::prepareParams(MACBaseParams & params) const
{
    if (params.input->getSize(MAC_PARAM_DIGEST_LENGTH, params.ctx, params.out_len)) {
        params.out_len = validateMacSize(params.out_len);
    }
    if (!_spec->truncate_mode) {
        // Truncate mode is off, so MAC supports custom size out of the box.
        OSSL_PARAM_BLD_push_size_t(params.builder, OSSL_MAC_PARAM_SIZE, params.out_len);
    }
    return true;
}

size_t MACBase::validateMacSize(size_t in_size) const
{
    if (_spec->truncate_mode) {
        // If truncate mode is ON, then size is limited by the default size.
        if (in_size > _spec->mac_size) {
            throw std::invalid_argument("Digest length is out of supported range");
        }
    }
    return in_size ? in_size : _spec->mac_size;
}

// Algorithm interface

const std::string & MACBase::getAlgorithmName() const
{
    return _spec->name;
}

void MACBase::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case MAC_PARAM_DIGEST_LENGTH: {
            _out_len = validateMacSize(value.asSize());
            return;
        }
        default:
            break;
    }
    throwUnsupportedParam(param_id);
}

Parameter MACBase::getParameter(int param_id) const
{
    switch (param_id) {
        case MAC_PARAM_DIGEST_LENGTH:
            return Parameter::take(_out_len);
            
        default:
            break;
    }
    throwUnsupportedParam(param_id);
}

} // cc7::crypto
} // cc7
