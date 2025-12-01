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

#include "OSSLObjects.h"
#include <cc7/crypto/CryptoException.h>

namespace cc7::crypto {

cc7::ByteArray BigNum_ToArray(const BigNum & bn)
{
    cc7::ByteArray array;
    array.resize(BN_num_bytes(bn));
    BN_bn2bin(bn, array.data());
    return array;
}

BigNum BigNum_FromArray(const cc7::ByteArray & array)
{
    return BigNum::take(BN_bin2bn(array.data(), (int)array.size(), nullptr));
}

ByteArray ECPoint_ToArray(const ECGroup & g, const ECPoint & p, point_conversion_form_t conversion, BNContext & ctx)
{
    auto point_size = EC_POINT_point2oct(g, p, conversion, nullptr, 0, ctx);
    if (!point_size) {
        throw CryptoException("Failed to get length of EC_POINT in bytes");
    }
    ByteArray out(point_size, 0);
    if (!EC_POINT_point2oct(g, p, conversion, out.data(), out.size(), ctx)) {
        throw CryptoException("Failed to convert EC_POINT to bytes");
    }
    return out;
}

void throwInvalidKey [[noreturn]] (const std::string & key_type);

void EVPKeyPair_CheckValid(const EVPKeyPair & key, const std::string & key_type)
{
    if (!key.isValid()) {
        throwInvalidKey(key_type);
    }
}

cc7::ByteArray EVPKeyPair_GetByteArrayParam(const EVPKeyPair & key, const char * param_name, bool allow_empty)
{
    cc7::ByteArray out;
    size_t data_len = 0;
    if (EVP_PKEY_get_octet_string_param(key, param_name, nullptr, 0, &data_len)) {
        out.resize(data_len);
        if (data_len && !EVP_PKEY_get_octet_string_param(key, param_name, out.data(), out.size(), &data_len)) {
            throw CryptoException("Failed to get EVP_PKEY parameter " + std::string(param_name));
        }
    } else {
        throw CryptoException("Failed to get EVP_PKEY parameter " + std::string(param_name));
    }
    if (!allow_empty && out.empty()) {
        throw CryptoException("Empty data returned for EVP_PKEY parameter " + std::string(param_name));
    }
    return out;
}

cc7::ByteArray EVPKeyPair_GetBigNumParam(const EVPKeyPair & key, const char * param_name)
{
    BIGNUM * value = nullptr;
    if (EVP_PKEY_get_bn_param(key, param_name, &value)) {
        return BigNum_ToArray(BigNum::take(value));
    }
    throw CryptoException("Failed to get EVP_PKEY parameter " + std::string(param_name));
}

std::string EVPKeyPair_GetStringParam(const EVPKeyPair & key, const char * param_name)
{
    std::string out;
    size_t data_len = 0;
    if (EVP_PKEY_get_utf8_string_param(key, param_name, nullptr, 0, &data_len)) {
        out.resize(data_len, ' ');
        if (data_len && !EVP_PKEY_get_utf8_string_param(key, param_name, const_cast<char*>(out.data()), out.size(), &data_len)) {
            throw CryptoException("Failed to get EVP_PKEY parameter " + std::string(param_name));
        }
    } else {
        throw CryptoException("Failed to get EVP_PKEY parameter " + std::string(param_name));
    }
    return out;
}

void EVPKeyPair_SetStringParam(const EVPKeyPair & key, const char * param_name, const std::string & value)
{
    if (!EVP_PKEY_set_utf8_string_param(key, param_name, value.c_str())) {
        throw CryptoException("Failed to set EVP_PKEY parameter " + std::string(param_name));
    }
}

std::string EVPKeyPair_GetGroupName(const EVPKeyPair & key)
{
    std::string out;
    size_t name_len = 0;
    if (EVP_PKEY_get_group_name(key, NULL, 0, &name_len) == 1) {
        cc7::ByteArray data;
        data.resize(name_len);
        if (EVP_PKEY_get_group_name(key, (char*)data.data(), data.size(), &name_len) != 1) {
            out.assign((const char*)data.data(), data.size());
        }
    }
    return out;
}

std::string EVPKeyPair_GetTypeName(const EVPKeyPair & key)
{
    auto name = EVP_PKEY_get0_type_name(key);
    return std::string(name ? name : "");
}

bool EVPKeyPair_ContainsPublicKey(const EVPKeyPair & key)
{
    size_t data_len = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &data_len) == 1) {
        return data_len > 0;
    }
    return false;
}

bool EVPKeyPair_ContainsPrivateKey(const EVPKeyPair & key)
{
    size_t data_len = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, nullptr, 0, &data_len) == 1) {
        return data_len > 0;
    }
    // If the key is not available as octet string, then try BIGNUM getter (for example EC keep private key as BIGNUM)
    BigNum bn;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, bn.objectRef()) == 1) {
        return bn.isValid();
    }
    return false;
}

} // namespace cc7::crypto
