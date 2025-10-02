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

#include "CryptoPrivate.h"
#include <openssl/provider.h>

namespace cc7 {
namespace crypto {

const std::string CryptoException::CLASS_NAME = "cc7::crypto::CryptoException";
const std::string UnsupportedAlgorithm::CLASS_NAME = "cc7::crypto::UnsupportedAlgorithm";
const std::string InternalError::CLASS_NAME = "cc7::crypto::InternalError";

void throwUnsupporterAlgorithm(const std::string & alg_name)
{
    throw UnsupportedAlgorithm("Unsupported algorithm " + alg_name);
}

void throwUnsupportedParam(int param_id)
{
    throw std::invalid_argument("Unsupported parameter ID=" + std::to_string(param_id));
}

void throwUnsupportedKeyFormat(const std::string & key_type, KeyFormat format)
{
    // TODO: distinguish between private / public / symmetric?
    throw std::invalid_argument(key_type + " doesn't support " + KeyFormat_ToString(format, true) + " conversion");
}

void throwInvalidKey(const std::string & key_type)
{
    throw std::invalid_argument(key_type + ": key is invalid");
}

void throwSealedKey(const std::string & key_type)
{
    throw CryptoException(key_type + ": private key is sealed");
}

bool stringHasPrefix(const std::string & str, const std::string & prefix)
{
    return str.size() >= prefix.size() &&
           str.compare(0, prefix.size(), prefix) == 0;
}

bool stringHasSuffix(const std::string & str, const std::string & suffix)
{
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

#define NULLCTX 1

class cc7CryptoInitializer {
public:
    
    OSSLCtx _ctx;
    OSSL_PROVIDER * _default;
    OSSL_PROVIDER * _base;
    
    static int callback(OSSL_PROVIDER *provider, void *cbdata)
    {
        auto name = OSSL_PROVIDER_get0_name(provider);
        printf("Provider name: %s\n", name);
        return 1;
    }
    
    static void dumpProviders(OSSL_LIB_CTX * ctx)
    {
        OSSL_PROVIDER_do_all(ctx, callback, nullptr);
    }
    
    cc7CryptoInitializer() {
#if NULLCTX == 0
        _ctx = OSSLCtx::empty();
        
        _default = OSSL_PROVIDER_load(_ctx, "default");
        _base = OSSL_PROVIDER_load(_ctx, "base");
        if (OSSL_PROVIDER_add_conf_parameter(_default, OSSL_PKEY_PARAM_ML_DSA_OUTPUT_FORMATS, "seed-only,priv-only,seed-priv") == 0) {
            throw CryptoException("Failed to alter OpenSSL configuration parameters");
        }
        if (OSSL_PROVIDER_add_conf_parameter(_base, OSSL_PKEY_PARAM_ML_DSA_OUTPUT_FORMATS, "seed-only,priv-only,seed-priv") == 0) {
            throw CryptoException("Failed to alter OpenSSL configuration parameters");
        }
        dumpProviders(_ctx);
#endif
    }
    
    ~cc7CryptoInitializer() {
        OSSL_PROVIDER_unload(_base);
        OSSL_PROVIDER_unload(_default);
    }
};

static cc7CryptoInitializer s_initializer;

OSSL_LIB_CTX * ossl_ctx()
{
#if NULLCTX == 1
    return nullptr;
#else
    if (s_initializer._ctx.isValid()) {
        return s_initializer._ctx.object();
    }
    throw CryptoException("OSSL_LIB_CTX is not initialized yet");
#endif
}

} // cc7::crypto
} // cc7
