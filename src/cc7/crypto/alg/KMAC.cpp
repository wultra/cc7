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

#include "KMAC.h"

namespace cc7 {
namespace crypto {

// MAC interface

static const MACBaseSpec KMAC_128 { "KMAC-128", "", 32, false };
static const MACBaseSpec KMAC_256 { "KMAC-256", "", 64, false };

std::shared_ptr<KMAC> KMAC::getInstance(const std::string & algorithm)
{
    const MACBaseSpec * spec;
    if (algorithm == KMAC_128.name) {
        spec = &KMAC_128;
    } else if (algorithm == KMAC_256.name) {
        spec = &KMAC_256;
    } else {
        return nullptr;
    }
    auto mac = EVPMac::take(EVP_MAC_fetch(ossl_ctx(), algorithm.c_str(), nullptr));
    if (!mac.isValid()) {
        throw CryptoException("Failed to fetch KMAC algorithm " + algorithm);
    }
    return std::shared_ptr<KMAC>(new KMAC(mac, spec));
}

// MARK: OSSLMAC interface

bool KMAC::prepareParams(MACBase::MACBaseParams & params) const
{
    ByteRange custom = _custom;
    params.input->getStringAsBytes(MAC_PARAM_CUSTOM_STRING, params.ctx, custom);
    params.input->getBytes(MAC_PARAM_CUSTOM_DATA, params.ctx, custom);
    if (!custom.empty()) {
        OSSL_PARAM_BLD_push_octet_string(params.builder, OSSL_MAC_PARAM_CUSTOM, custom.data(), custom.size());
    }
    return MACBase::prepareParams(params);
}


// MARK: Algorithm interface

void KMAC::setParameter(int param_id, const Parameter &value)
{
    switch (param_id) {
        case MAC_PARAM_CUSTOM_STRING:
            _custom = MakeRange(value.asString());
            return;
        case MAC_PARAM_CUSTOM_DATA:
            _custom = value.asByteRange();
            return;
            
        default:
            break;
    }
    MACBase::setParameter(param_id, value);
}

Parameter KMAC::getParameter(int param_id) const
{
    switch (param_id) {
        case MAC_PARAM_CUSTOM_STRING:
            return Parameter::copy(CopyToString(_custom));
        case MAC_PARAM_CUSTOM_DATA:
            return Parameter::ref(_custom);
            
        default:
            break;
    }
    return MACBase::getParameter(param_id);
}


} // cc7::crypto
} // cc7
