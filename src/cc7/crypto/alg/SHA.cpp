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

#include "SHA.h"
#include <openssl/sha.h>

namespace cc7 {
namespace crypto {

static const SHASpec SHA_256  = { "SHA-256" , 32, EVP_sha256()  };
static const SHASpec SHA_384  = { "SHA-384" , 48, EVP_sha384()  };
static const SHASpec SHA_512  = { "SHA-512" , 64, EVP_sha512()  };
static const SHASpec SHA3_256 = { "SHA3-256", 32, EVP_sha3_256() };
static const SHASpec SHA3_384 = { "SHA3-384", 48, EVP_sha3_384() };
static const SHASpec SHA3_512 = { "SHA3-512", 64, EVP_sha3_512() };

static const std::vector<const SHASpec*> spec_list = {
    &SHA3_256, &SHA3_384, &SHA3_512,
    &SHA_256,  &SHA_384,  &SHA_512,
};

static const SHASpec * algorithmToSpec(const std::string & algorithm)
{
    for (auto spec : spec_list) {
        if (spec->name == algorithm) {
            return spec;
        }
    }
    return nullptr;
}

std::shared_ptr<SHA> SHA::getInstance(const std::string & algorithm)
{
    auto spec = algorithmToSpec(algorithm);
    if (!spec) {
        return nullptr;
    }
    return std::shared_ptr<SHA>(new SHA(spec));
}

// MessageDigest interface

ByteArray SHA::digest(const ByteRange & input, const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    cc7::ByteArray hash(_spec->digest_size, 0);
    auto ctx = EVPMDContext::empty();
    EVP_DigestInit(ctx, _spec->md);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal(ctx, hash.data(), NULL);
    return hash;
}


// Algorithm interface

const std::string & SHA::getAlgorithmName() const
{
    return _spec->name;
}

void SHA::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter SHA::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

} // cc7::crypto
} // cc7
