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

#include "JwsBaseAlgorithm.h"
#include "JwsDsaSignature.h"
#include "JwsMacSignature.h"

namespace cc7::jwt {

JwsBaseAlgorithm::JwsBaseAlgorithm(const JwsSpec* spec) :
    _spec(spec)
{
}

const JwsSpec* JwsBaseAlgorithm::getSpec() const
{
    return _spec;
}

JwsAlgorithmPtr JwsBaseAlgorithm::getInstance(const std::string& algorithm)
{
    const auto spec = JwsSpec::specForJwsAlgorithm(algorithm);
    if (!spec) {
        throw JwtException("Unsupported algorithm " + algorithm);
    }
    switch (spec->type) {
        case JwsSpec::Type::MAC: {
            auto mac = crypto::MAC::getInstance(spec->algorithm);
            return std::make_shared<JwsMacSignature>(mac, spec);
        }
        case JwsSpec::Type::DSA: {
            auto dsa = crypto::Signature::getInstance(spec->algorithm);
            return std::make_shared<JwsDsaSignature>(dsa, spec);;
        }
    }
}

} // namespace cc7::jwt
