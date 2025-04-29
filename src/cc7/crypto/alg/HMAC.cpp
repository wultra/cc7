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

#include "HMAC.h"

namespace cc7
{
namespace crypto
{

static const MACBaseSpec HMAC_SHA_256  = { "HMAC-SHA-256",  "SHA-256",  32, true };
static const MACBaseSpec HMAC_SHA_384  = { "HMAC-SHA-384",  "SHA-384",  48, true };
static const MACBaseSpec HMAC_SHA_512  = { "HMAC-SHA-512",  "SHA-512",  64, true };
static const MACBaseSpec HMAC_SHA3_256 = { "HMAC-SHA3-256", "SHA3-256", 32, true };
static const MACBaseSpec HMAC_SHA3_384 = { "HMAC-SHA3-384", "SHA3-384", 48, true };
static const MACBaseSpec HMAC_SHA3_512 = { "HMAC-SHA3-512", "SHA3-512", 64, true };

static const std::vector<const MACBaseSpec*> alg_list = {
    &HMAC_SHA3_256, &HMAC_SHA3_384, &HMAC_SHA3_512,
    &HMAC_SHA_256,  &HMAC_SHA_384,  &HMAC_SHA_512,
};

static const MACBaseSpec * algorithmToSpec(const std::string & algorithm)
{
    for (auto spec : alg_list) {
        if (spec->name == algorithm) {
            return spec;
        }
    }
    return nullptr;
}

// MAC interface

std::shared_ptr<HMAC> HMAC::getInstance(const std::string & algorithm)
{
    auto spec = algorithmToSpec(algorithm);
    if (!spec) {
        return nullptr;
    }
    auto mac = LLMac::take(EVP_MAC_fetch(ossl_ctx(), "HMAC", nullptr));
    if (!mac.isValid()) {
        throw std::domain_error("Failed to fetch HMAC algorithm");
    }
    return std::shared_ptr<HMAC>(new HMAC(mac, spec));
}

// MARK: OSSLMAC interface

bool HMAC::prepareParams(OSSL_PARAM_BLD *builder) const
{
    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_MAC_PARAM_DIGEST, _spec->md_name.c_str(), _spec->md_name.size());
    return MACBase::prepareParams(builder);
}

} // cc7::crypto
} // cc7
