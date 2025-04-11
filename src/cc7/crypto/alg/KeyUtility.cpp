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

#include "KeyUtility.h"

namespace cc7
{
namespace crypto
{

static void throwImportFailure [[noreturn]] (const std::string & key_type, bool is_public)
{
    auto message = std::string("Failed to import ");
    message += key_type;
    message += is_public ? " public key" : "private key";
    throw std::domain_error(message);
}

static void throwExportFailure [[noreturn]] (const std::string & key_type, bool is_public)
{
    auto message = std::string("Failed to export ");
    message += key_type;
    message += is_public ? " public key" : "private key";
    throw std::domain_error(message);
}

EVPKeyPair importKeyFromDER(const std::string & key_type, bool is_public, const ByteRange & key_data)
{
    EVP_PKEY * pkey = NULL;
    auto select = is_public ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY : OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    auto ctx = OSSLDecoderContext::take(OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", nullptr, key_type.c_str(), select, nullptr, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to init DER key decoder");
    }
    const unsigned char * data_ptr = key_data.data();
    size_t data_len = key_data.size();
    if (OSSL_DECODER_from_data(ctx, &data_ptr, &data_len) != 1 || pkey == nullptr) {
        throwImportFailure(key_type, is_public);
    }
    return EVPKeyPair::take(pkey);
}

EVPKeyPair importRawKey(const std::string & key_type, bool is_public, const ByteRange & key_data)
{
    auto pkey = is_public
                    ? EVP_PKEY_new_raw_public_key_ex(nullptr, key_type.c_str(), nullptr, key_data.data(), key_data.size())
                    : EVP_PKEY_new_raw_private_key_ex(nullptr, key_type.c_str(), nullptr, key_data.data(), key_data.size());
    if (pkey == nullptr) {
        throwImportFailure(key_type, is_public);
    }
    return EVPKeyPair::take(pkey);
}

ByteArray exportKeyToDER(const EVPKeyPair & pkey, const std::string & key_type, bool is_public)
{
    if (!pkey.isValid()) {
        throwInvalidKey(key_type);
    }
    auto selection = is_public ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY : OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    auto output_struct = is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo";
    auto ctx = OSSLEncoderContext::take(OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", output_struct, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to init DER key encoder");
    }

    unsigned char *pdata = nullptr;
    size_t pdata_len = 0;
    if (OSSL_ENCODER_to_data(ctx, &pdata, &pdata_len) != 1) {
        throwExportFailure(key_type, is_public);
    }
    return ByteArray(ByteRange(pdata, pdata_len));
}

ByteArray exportKeyToRaw(const EVPKeyPair & pkey, const std::string & key_type, bool is_public)
{
    if (!pkey.isValid()) {
        throwInvalidKey(key_type);
    }
    auto param = is_public ? OSSL_PKEY_PARAM_PUB_KEY : OSSL_PKEY_PARAM_PRIV_KEY;
    try {
        return getByteArrayKeyParameter(pkey, param);
    } catch (std::exception e) {
        throwExportFailure(key_type, is_public);
    }
}

} // cc7::crypto
} // cc7
