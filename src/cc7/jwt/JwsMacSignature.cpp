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

#include "JwsMacSignature.h"

namespace cc7 {
namespace jwt {

crypto::ParameterList JwsMacSignature::buildParamsForSpec(const JwsSpec* spec)
{
    crypto::ParameterList params;
    if (spec->sizeParam) {
        params[crypto::MAC_PARAM_DIGEST_LENGTH] = crypto::Parameter::take(spec->sizeParam);
    };
    if (!spec->stringParam.empty()) {
        params[crypto::MAC_PARAM_CUSTOM_STRING] = crypto::Parameter::ref(spec->stringParam);
    }
    return params;
}


JwsMacSignature::JwsMacSignature(const crypto::MACPtr& mac, const JwsSpec * spec) :
    JwsBaseAlgorithm(spec),
    _mac(mac),
    _mac_params(buildParamsForSpec(spec))
{
}

ByteArray JwsMacSignature::sign(const JwsKey &key, const ByteRange &data) const
{
    return _mac->token(key.getSymmetricKey(), data, _mac_params);
}

bool JwsMacSignature::verify(const JwsKey &key, const ByteRange &data, const ByteRange &signature) const
{
    return _mac->verifyToken(key.getSymmetricKey(), data, signature, _mac_params);
}

} // namespace jwt
} // namespace cc7
