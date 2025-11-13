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

#pragma once

#include <cc7/ByteArray.h>

#include "LLObject.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hpke.h>

namespace cc7 {
namespace crypto {

// EVP

/// The `EVPKeyPair` is wrapper for `EVP_PKEY`.
typedef TLLRefObject<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_up_ref, EVP_PKEY_free> EVPKeyPair;

void        EVPKeyPair_CheckValid(const EVPKeyPair & key, const std::string & key_type);
ByteArray   EVPKeyPair_GetByteArrayParam(const EVPKeyPair & key, const char * param_name, bool allow_empty = true);
ByteArray   EVPKeyPair_GetBigNumParam(const EVPKeyPair & key, const char * param_name);
std::string EVPKeyPair_GetStringParam(const EVPKeyPair & key, const char * param_name);
void        EVPKeyPair_SetStringParam(const EVPKeyPair & key, const char * param_name, const std::string & value);
std::string EVPKeyPair_GetGroupName(const EVPKeyPair & key);
std::string EVPKeyPair_GetTypeName(const EVPKeyPair & key);
bool        EVPKeyPair_ContainsPublicKey(const EVPKeyPair & key);
bool        EVPKeyPair_ContainsPrivateKey(const EVPKeyPair & key);

/// The `EVPKeyPairCtx` is wrapper for `EVP_PKEY_CTX`.
typedef TLLObject<EVP_PKEY_CTX, nullptr, EVP_PKEY_CTX_free> EVPKeyPairContext;

/// The `EVPMDContext` is wrapper for `EVP_MD_CTX`.
typedef TLLObject<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free> EVPMDContext;

/// The `EVPCipher` is wrapper for `EVP_CIPHER`.
typedef TLLRefObject<EVP_CIPHER, nullptr, EVP_CIPHER_up_ref, EVP_CIPHER_free> EVPCipher;

/// The `EVPCipherContext` is wrapper for `EVP_CIPHER_CTX`.
typedef TLLObject<EVP_CIPHER_CTX, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free> EVPCipherContext;

/// The `EVPSignature` is wrapper for `EVP_SIGNATURE`.
typedef TLLRefObject<EVP_SIGNATURE, nullptr, EVP_SIGNATURE_up_ref, EVP_SIGNATURE_free> EVPSignature;

/// The `EVPKdf` is wrapper for `EVP_KDF`.
typedef TLLObject<EVP_KDF, nullptr, EVP_KDF_free> EVPKdf;

/// The `EVPKdfContext` is wrapper for `EVP_KDF_CTX`.
typedef TLLObject<EVP_KDF_CTX, nullptr, EVP_KDF_CTX_free> EVPKdfContext;

/// The `EVPMac` is wrapper for `EVP_MAC`.
typedef TLLRefObject<EVP_MAC, nullptr, EVP_MAC_up_ref, EVP_MAC_free> EVPMac;

/// The `EVPMacContext` is wrapper for `EVP_MAC_CTX`.
typedef TLLObject<EVP_MAC_CTX, nullptr, EVP_MAC_CTX_free> EVPMacContext;

/// The `OSSLHpkeContext` is wrapper for `OSSL_HPKE_CTX`.
typedef TLLObject<OSSL_HPKE_CTX, nullptr, OSSL_HPKE_CTX_free> HPKEContext;


// OSSL

/// The `OSSLParamBuilder` is wrapper for `OSSL_PARAM_BLD`.
typedef TLLObject<OSSL_PARAM_BLD, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_free> OSSLParamBuilder;

/// The `OSSLParam` is wrapper for `OSSL_PARAM`.
typedef TLLObject<OSSL_PARAM, nullptr, OSSL_PARAM_free> OSSLParam;

/// The `OSSLDecoderContext` is wrapper for `OSSL_DECODER_CTX`.
typedef TLLObject<OSSL_DECODER_CTX, nullptr, OSSL_DECODER_CTX_free> OSSLDecoderContext;

/// The `OSSLEncoderContext` is wrapper for `OSSL_ENCODER_CTX`.
typedef TLLObject<OSSL_ENCODER_CTX, nullptr, OSSL_ENCODER_CTX_free> OSSLEncoderContext;

/// The `OSSLCtx` is wrapper for `OSSL_LIB_CTX`.
typedef TLLObject<OSSL_LIB_CTX, OSSL_LIB_CTX_new, OSSL_LIB_CTX_free> OSSLCtx;


// Other

/// The `BigNum` is wrapper for `BIGNUM`.
typedef TLLObject<BIGNUM, BN_secure_new, BN_free> BigNum;

/// The `BNContext` is wrapper for `BN_CTX`.
typedef TLLObject<BN_CTX, BN_CTX_new, BN_CTX_free> BNContext;

ByteArray BigNum_ToArray(const BigNum & bn);
BigNum BigNum_FromArray(const cc7::ByteArray & array);

/// The `ECPoint` is wrapper for `EC_POINT`.
typedef TLLObject<EC_POINT, nullptr, EC_POINT_free> ECPoint;

/// The `ECGroup` is wrapper for `EC_GROUP`.
typedef TLLObject<EC_GROUP, nullptr, EC_GROUP_free> ECGroup;

ByteArray ECPoint_ToArray(const ECGroup & g, const ECPoint & p, point_conversion_form_t conversion, BNContext & ctx);

/// The `OSSLBIO` is wrapper for `BIO` structure.
typedef TLLObject<BIO, nullptr, TWrapIntToVoid<BIO, BIO_free>> OSSLBIO;

/// The `OSSLBuf` is wrapper for `BUF_MEM` structure. If ::empty() is called, then buffer containing sensitive 
typedef TLLObject<BUF_MEM, TFuncWithParam1<BUF_MEM, unsigned long, BUF_MEM_new_ex, BUF_MEM_FLAG_SECURE>, BUF_MEM_free> OSSLBuf;


#if DEBUG
    #define OSSL_print_errors() ERR_print_errors_fp(stderr)
#else
    #define OSSL_print_errors()
#endif

} // cc7::crypto
} // cc7
