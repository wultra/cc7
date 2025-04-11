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

namespace cc7
{
namespace crypto
{

void throwUnsupporterAlgorithm(const std::string & alg_name)
{
    throw std::invalid_argument("Unsupported algorithm " + alg_name);
}

void throwUnsupportedParam(int param_id)
{
    throw std::invalid_argument("Unsupported parameter ID=" + std::to_string(param_id));
}

void throwUnsupportedKeyConversion(const std::string & key_type, const std::string & conv_format)
{
    throw std::invalid_argument(key_type + ": doesn't support import export conversion " + conv_format);
}

void throwInvalidKey(const std::string & key_type)
{
    throw std::invalid_argument(key_type + ": key is invalid");
}
    
bool stringHasPrefix(const std::string & str, const std::string & prefix)
{
    return str.size() >= prefix.size() &&
           str.compare(0, prefix.size(), prefix) == 0;
}

cc7::ByteArray getByteArrayKeyParameter(const EVPKeyPair & key, const char * param_name)
{
    cc7::ByteArray out;
    size_t data_len = 0;
    if (EVP_PKEY_get_octet_string_param(key, param_name, nullptr, 0, &data_len)) {
        out.resize(data_len);
        if (!EVP_PKEY_get_octet_string_param(key, param_name, out.data(), out.size(), &data_len)) {
            throw std::domain_error("Failed to get EVP_PKEY parameter " + std::string(param_name));
        }
    } else {
        throw std::domain_error("Failed to get EVP_PKEY parameter " + std::string(param_name));
    }
    return out;
}
    
} // cc7::crypto
} // cc7
