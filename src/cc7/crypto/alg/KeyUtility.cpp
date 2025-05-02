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
#include <map>
#include <algorithm>

#include <openssl/x509.h>

namespace cc7
{
namespace crypto
{

// MARK: - Forward declarations

struct KeyFormatEntry;
struct KeyFormatSpec;

static ByteArray  raw_pub_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
static ByteArray  raw_priv_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
static EVPKeyPair raw_pub_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);
static EVPKeyPair raw_priv_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);

static ByteArray  pkcs8_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
static EVPKeyPair pkcs8_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);
static EVPKeyPair spki_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);
static ByteArray  spki_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);

static ByteArray  sec1_priv_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
static EVPKeyPair sec1_priv_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);

static ByteArray  ec_raw_pub_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
static ByteArray  ec_raw_priv_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
static EVPKeyPair ec_raw_pub_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);
static EVPKeyPair ec_raw_priv_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);

static bool ec_validate_imported_public(const EVPKeyPair & pkey, const KeyFormatEntry & entry, const KeyFormatSpec & spec);
static bool ec_validate_imported_private(const EVPKeyPair & pkey, const KeyFormatEntry & entry, const KeyFormatSpec & spec);

// MARK: - Mapping table

struct KeyFormatParam
{
    enum Type {
        T_Void,
        T_Int,
        T_Str
    };
    
    Type type;
    union {
        const void * ptr;
        int int_param;
        const char * str_param;
    };
    
    KeyFormatParam()                : type(T_Void) { ptr = nullptr; }
    KeyFormatParam(int v)           : type(T_Int) { int_param = v; }
    KeyFormatParam(const char * v)  : type(T_Str) { str_param = v; }
    
    KeyFormatParam(const KeyFormatParam & other) {
        type = other.type;
        ptr = other.ptr;
    }
    
    const char * asStr() const {
        checkType(T_Str);
        return str_param;
    }
    
    int asInt() const {
        checkType(T_Int);
        return int_param;
    }
    
    bool isSet() const {
        return type != T_Void;
    }
    
    void checkType(Type t) const {
        if (t != type) throw std::domain_error("Wrong param in key export/import mapping table");
    }
};

typedef ByteArray  (*KeyExportFunc)(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key);
typedef EVPKeyPair (*KeyImportFunc)(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data);
typedef bool       (*KeyValidateFunc)(const EVPKeyPair & pkey, const KeyFormatEntry & entry, const KeyFormatSpec & spec);
struct KeyFormatEntry;
struct KeyFormatSpec
{
    KeyFormat format;
    KeyExportFunc publicExportFunc;
    KeyImportFunc publicImportFunc;
    KeyExportFunc privateExportFunc;
    KeyImportFunc privateImportFunc;
};

struct KeyFormatEntry
{
    std::string key_type;
    std::string ossl_type_name;
    KeyFormat pub_default;
    KeyFormat priv_format;
    std::vector<KeyFormatSpec> formatters;
    KeyValidateFunc public_validate_func;
    KeyValidateFunc private_validate_func;
    KeyFormatParam entry_param1;
    KeyFormatParam entry_param2;
};

// Key import / export mapping

static const std::vector<KeyFormatEntry> s_mapping {
    // ML-DSA
    {
        "ML-DSA-44",
        "ML-DSA-44",
        KEY_FORMAT_SPKI, KEY_FORMAT_PKCS8,       // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_PKCS8, nullptr,          nullptr,          pkcs8_export,      pkcs8_import      },
            { KEY_FORMAT_SPKI,  spki_export,      spki_import,      nullptr,           nullptr           },
            { KEY_FORMAT_RAW,   raw_pub_export,   raw_pub_import,   raw_priv_export,   raw_priv_import   },
        }
    },{
        "ML-DSA-65",
        "ML-DSA-65",
        KEY_FORMAT_SPKI, KEY_FORMAT_PKCS8,       // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_PKCS8, nullptr,          nullptr,          pkcs8_export,      pkcs8_import      },
            { KEY_FORMAT_SPKI,  spki_export,      spki_import,      nullptr,           nullptr           },
            { KEY_FORMAT_RAW,   raw_pub_export,   raw_pub_import,   raw_priv_export,   raw_priv_import   },
        }
    },{
        "ML-DSA-87",
        "ML-DSA-87",
        KEY_FORMAT_SPKI, KEY_FORMAT_PKCS8,       // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_PKCS8, nullptr,          nullptr,          pkcs8_export,      pkcs8_import      },
            { KEY_FORMAT_SPKI,  spki_export,      spki_import,      nullptr,           nullptr           },
            { KEY_FORMAT_RAW,   raw_pub_export,   raw_pub_import,   raw_priv_export,   raw_priv_import   },

        }
    
    },
    // ML-KEM
    {
        "ML-KEM-512",
        "ML-KEM-512",
        KEY_FORMAT_RAW, KEY_FORMAT_RAW,         // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_RAW,   raw_pub_export,   raw_pub_import,   raw_priv_export,   raw_priv_import   },
        }
    },
    {
        "ML-KEM-768",
        "ML-KEM-768",
        KEY_FORMAT_RAW, KEY_FORMAT_RAW,         // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_RAW,   raw_pub_export,   raw_pub_import,   raw_priv_export,   raw_priv_import   },
        }
    },
    {
        "ML-KEM-1024",
        "ML-KEM-1024",
        KEY_FORMAT_RAW, KEY_FORMAT_RAW,         // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_RAW,   raw_pub_export,   raw_pub_import,   raw_priv_export,   raw_priv_import   },
        }
    },
    // EC keys
    {
        "P-256",
        "EC",
        KEY_FORMAT_SPKI, KEY_FORMAT_PKCS8,       // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_PKCS8, nullptr,           nullptr,           pkcs8_export,       pkcs8_import       },
            { KEY_FORMAT_SPKI,  spki_export,       spki_import,       nullptr,            nullptr            },
            { KEY_FORMAT_SEC1,  nullptr,           nullptr,           sec1_priv_export,   sec1_priv_import   },
            { KEY_FORMAT_X963,  ec_raw_pub_export, ec_raw_pub_import, nullptr,            nullptr   },
            { KEY_FORMAT_RAW,   ec_raw_pub_export, ec_raw_pub_import, ec_raw_priv_export, ec_raw_priv_import },
        },
        ec_validate_imported_public, ec_validate_imported_private,
        KeyFormatParam("prime256v1"), KeyFormatParam(NID_X9_62_prime256v1)
    },
    {
        "P-384",
        "EC",
        KEY_FORMAT_SPKI, KEY_FORMAT_PKCS8,       // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_PKCS8, nullptr,           nullptr,           pkcs8_export,       pkcs8_import       },
            { KEY_FORMAT_SPKI,  spki_export,       spki_import,       nullptr,            nullptr            },
            { KEY_FORMAT_SEC1,  nullptr,           nullptr,           sec1_priv_export,   sec1_priv_import   },
            { KEY_FORMAT_X963,  ec_raw_pub_export, ec_raw_pub_import, nullptr,            nullptr   },
            { KEY_FORMAT_RAW,   ec_raw_pub_export, ec_raw_pub_import, ec_raw_priv_export, ec_raw_priv_import },
        },
        ec_validate_imported_public, ec_validate_imported_private,
        KeyFormatParam("secp384r1"), KeyFormatParam(NID_secp384r1)
    },
    {
        "P-521",
        "EC",
        KEY_FORMAT_SPKI, KEY_FORMAT_PKCS8,       // defaults
        std::vector<KeyFormatSpec> {
            { KEY_FORMAT_PKCS8, nullptr,           nullptr,           pkcs8_export,       pkcs8_import       },
            { KEY_FORMAT_SPKI,  spki_export,       spki_import,       nullptr,            nullptr            },
            { KEY_FORMAT_SEC1,  nullptr,           nullptr,           sec1_priv_export,   sec1_priv_import   },
            { KEY_FORMAT_X963,  ec_raw_pub_export, ec_raw_pub_import, nullptr,            nullptr   },
            { KEY_FORMAT_RAW,   ec_raw_pub_export, ec_raw_pub_import, ec_raw_priv_export, ec_raw_priv_import },
        },
        ec_validate_imported_public, ec_validate_imported_private,
        KeyFormatParam("secp521r1"), KeyFormatParam(NID_secp521r1)
    }
};

// MARK: - Lookup

static void throwImportExportFailure [[noreturn]] (const std::string & key_type, KeyFormat format, bool is_export, bool is_public)
{
    auto message = std::string("Failed to");
    message += is_export ? " export " : " import ";
    message += key_type;
    message += is_public ? " public key" : " private key";
    message += is_export ? " to " : " from ";
    message += KeyFormat_ToString(format, true);
    throw std::domain_error(message);
}

// Entry lookup

static std::pair<const KeyFormatEntry *, const KeyFormatSpec *> findEntry(const std::string & key_type, KeyFormat format, bool is_public)
{
    // Look for entry
    auto entry_it = std::find_if(s_mapping.begin(), s_mapping.end(), [&key_type](const KeyFormatEntry& entry) {
        return entry.key_type == key_type;
    });
    if (entry_it == s_mapping.end()) {
        throwUnsupporterAlgorithm(key_type);
    }
    // Patch default format
    if (format == KEY_FORMAT_DEFAULT) {
        format = is_public ? entry_it->pub_default : entry_it->priv_format;
    }
    // Look for format specification
    auto form_it = std::find_if(entry_it->formatters.begin(), entry_it->formatters.end(), [format](const KeyFormatSpec & spec) {
        return spec.format == format;
    });
    if (form_it == entry_it->formatters.end()) {
        throwUnsupportedKeyFormat(key_type, format);
    }
    return std::make_pair(&*entry_it, &*form_it);
}

static ByteArray exportImpl(const EVPKeyPair & pkey, const std::string & key_type, KeyFormat key_format, bool is_public)
{
    if (!pkey.isValid()) {
        throwInvalidKey(key_type);
    }
    auto entry = findEntry(key_type, key_format, is_public);
    auto exportFunc = is_public ? entry.second->publicExportFunc : entry.second->privateExportFunc;
    if (!exportFunc) {
        // Conversion is not supported for public or private key
        throwUnsupportedKeyFormat(key_type, key_format);
    }
    ByteArray out;
    try {
        out = exportFunc(*entry.first, *entry.second, pkey);
    } catch (std::exception & e) {
        CC7_LOG("crypto: Key export function failed: %s", e.what());
    }
    if (out.empty()) {
        throwImportExportFailure(key_type, entry.second->format, true, is_public);
    }
    return out;
}

static EVPKeyPair importImpl(const std::string & key_type, KeyFormat key_format, const ByteRange & key_data, bool is_public)
{
    if (key_data.empty()) {
        throw std::invalid_argument("Cannot import key from empty byte array");
    }
    auto entry = findEntry(key_type, key_format, is_public);
    auto importFunc = is_public ? entry.second->publicImportFunc : entry.second->privateImportFunc;
    if (!importFunc) {
        // Conversion is not supported for public or private key
        throwUnsupportedKeyFormat(key_type, key_format);
    }
    EVPKeyPair pkey;
    try {
        pkey = importFunc(*entry.first, *entry.second, key_data);
    } catch (std::exception & e) {
        CC7_LOG("crypto: Key import function failed: %s", e.what());
    }
    // Validate key type
    if (pkey.isValid()) {
        auto key_type_name = EVPKeyPair_GetTypeName(pkey);
        if (entry.first->ossl_type_name != key_type_name) {
            CC7_LOG("crypto: Imported key has unexpected type");
            pkey.destroy();
        }
    }
    // Perform custom validation
    if (pkey.isValid()) {
        auto validateFunc = is_public ? entry.first->public_validate_func : entry.first->private_validate_func;
        if (validateFunc) {
            if (!validateFunc(pkey, *entry.first, *entry.second)) {
                pkey.destroy();
            }
        }
    }
    // Check whether right key was imported
    if (pkey.isValid()) {
        if (!(is_public ? EVPKeyPair_ContainsPublicKey(pkey) : EVPKeyPair_ContainsPrivateKey(pkey))) {
            if (is_public) {
                CC7_LOG("crypto: No public key imported");
            } else {
                CC7_LOG("crypto: No private key imported");
            }
            pkey.destroy();
        }
    }
    if (!pkey.isValid()) {
        throwImportExportFailure(key_type, entry.second->format, false, is_public);
    }
    return pkey;
}

// MARK: RAW format

static ByteArray  raw_pub_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    return EVPKeyPair_GetByteArrayParam(key, OSSL_PKEY_PARAM_PUB_KEY);
}

static ByteArray  raw_priv_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    return EVPKeyPair_GetByteArrayParam(key, OSSL_PKEY_PARAM_PRIV_KEY);
}

static EVPKeyPair raw_pub_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    return EVPKeyPair::take(EVP_PKEY_new_raw_public_key_ex(ossl_ctx(), entry.key_type.c_str(), nullptr, key_data.data(), key_data.size()));
}

static EVPKeyPair raw_priv_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    return EVPKeyPair::take(EVP_PKEY_new_raw_private_key_ex(ossl_ctx(), entry.key_type.c_str(), nullptr, key_data.data(), key_data.size()));
}


// MARK: Common der routines

static ByteArray der_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key, const char * structure, int selection)
{
    auto ctx = OSSLEncoderContext::take(OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER", structure, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to init DER key encoder");
    }
    unsigned char *pdata = nullptr;
    size_t pdata_len = 0;
    ByteArray out;
    if (OSSL_ENCODER_to_data(ctx, &pdata, &pdata_len) == 1) {
        out = ByteRange(pdata, pdata_len);
    }
    return out;
}

static EVPKeyPair der_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data, int selection)
{
    EVPKeyPair result;
    auto key_type_str = entry.ossl_type_name.c_str();
    auto ctx = OSSLDecoderContext::take(OSSL_DECODER_CTX_new_for_pkey(result.objectRef(), "DER", nullptr, key_type_str, selection, ossl_ctx(), nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to init DER key decoder");
    }
    const unsigned char * data_ptr = key_data.data();
    size_t data_len = key_data.size();
    if (OSSL_DECODER_from_data(ctx, &data_ptr, &data_len) != 1) {
        result.destroy();
    }
    return result;
}

// MARK: PKCS#8 / SPKI formats

static ByteArray pkcs8_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    return der_export(entry, spec, key, "PrivateKeyInfo", OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
}

static EVPKeyPair pkcs8_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    return der_import(entry, spec, key_data, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
}

static ByteArray  spki_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    return der_export(entry, spec, key, "SubjectPublicKeyInfo", OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
}

static EVPKeyPair spki_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    return der_import(entry, spec, key_data, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
}

// MARK: EC RAW format

static bool ec_pub_key_validate(const EVPKeyPair & key)
{
    BIGNUM * coord_x = nullptr;
    BIGNUM * coord_y = nullptr;
    // Extract X
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &coord_x)) {
        return false;
    }
    auto x = BigNum::take(coord_x);
    // Extract Y
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &coord_y)) {
        return false;
    }
    auto y = BigNum::take(coord_y);
    // Check infinity
    if (BN_is_zero(x) || BN_is_zero(y)) {
        return false;
    }
    return true;
}

static ByteArray  ec_raw_pub_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    return EVPKeyPair_GetByteArrayParam(key, OSSL_PKEY_PARAM_PUB_KEY, false);
}

static ByteArray  ec_raw_priv_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    return EVPKeyPair_GetBigNumParam(key, OSSL_PKEY_PARAM_PRIV_KEY);
}

static EVPKeyPair ec_raw_pub_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    auto builder = OSSLParamBuilder::empty();
    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, entry.key_type.c_str(), 0);
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, key_data.data(), key_data.size());
    
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(ossl_ctx(), "EC", nullptr));
    if (!ctx.isValid() || EVP_PKEY_fromdata_init(ctx) <= 0) {
        throw std::domain_error("Failed to get and initialize EC public key context");
    }
    EVPKeyPair result;
    if (EVP_PKEY_fromdata(ctx, result.objectRef(), EVP_PKEY_PUBLIC_KEY, params) == 1) {
        if (!ec_pub_key_validate(result)) {
            throw std::domain_error("Invalid EC public key");
        }
    } else {
        result.destroy();
    }
    return result;
}

static EVPKeyPair ec_raw_priv_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    // RAW format
    auto builder = OSSLParamBuilder::empty();
    auto priv_key_bn = BigNum_FromArray(key_data);
    auto group = ECGroup::take(EC_GROUP_new_by_curve_name(entry.entry_param2.asInt()));
    auto pub_point = ECPoint::take(EC_POINT_new(group));
    if (!group.isValid() || !pub_point.isValid()) {
        throw std::domain_error("Failed to allocate EC group or EC point");
    }
    
    auto bn_ctx = BNContext::empty();
    if (!EC_POINT_mul(group, pub_point, priv_key_bn, nullptr, nullptr, bn_ctx)) {
        throw std::domain_error("Failed to calculate EC public key from private key");
    }
    auto pub_key_bytes = ECPoint_ToArray(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);

    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, entry.key_type.c_str(), 0);
    OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, priv_key_bn);
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, pub_key_bytes.data(), pub_key_bytes.size());
    
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(ossl_ctx(), "EC", nullptr));
    if (!ctx.isValid() || EVP_PKEY_fromdata_init(ctx) <= 0) {
        throw std::domain_error("Failed to get and initialize EC public key context");
    }
    EVPKeyPair result;
    if (EVP_PKEY_fromdata(ctx, result.objectRef(), EVP_PKEY_KEYPAIR, params) != 1) {
        result.destroy();
    }
    return result;
}

// MARK: SEC1 format

static ByteArray  sec1_priv_export(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const EVPKeyPair & key)
{
    auto length = i2d_PrivateKey(key, nullptr);
    if (length <= 0) {
        throw std::domain_error("Failed to get length of SEC1 key");
    }
    ByteArray out(length, 0);
    unsigned char *p = out.data();
    if (i2d_PrivateKey(key, &p) < 0) {
        throw std::domain_error("Failed to export SEC1 key");
    }
    return out;
}

static EVPKeyPair sec1_priv_import(const KeyFormatEntry & entry, const KeyFormatSpec & spec, const ByteRange & key_data)
{
    // TODO: validate this...
    const unsigned char *p = key_data.data();
    return EVPKeyPair::take(d2i_PrivateKey_ex(EVP_PKEY_EC, nullptr, &p, key_data.size(), ossl_ctx(), nullptr));
}

bool ec_validate_imported_public(const EVPKeyPair & pkey, const KeyFormatEntry & entry, const KeyFormatSpec & spec)
{
    // Validate curve first
    if (entry.entry_param1.asStr() != EVPKeyPair_GetGroupName(pkey)) {
        CC7_LOG("Key with different curve imported");
        return false;
    }
    // Validate public key
    if (!ec_pub_key_validate(pkey)) {
        CC7_LOG("Invalid EC public key");
        return false;
    }
    return true;
}

bool ec_validate_imported_private(const EVPKeyPair & pkey, const KeyFormatEntry & entry, const KeyFormatSpec & spec)
{
    // Validate curve
    if (entry.entry_param1.asStr() != EVPKeyPair_GetGroupName(pkey)) {
        CC7_LOG("Key with different curve imported");
        return false;
    }
    return true;
}

// MARK: - Public API

ByteArray  exportPublicKey(const EVPKeyPair & pkey, const std::string & key_type, KeyFormat key_format)
{
    return exportImpl(pkey, key_type, key_format, true);
}

ByteArray  exportPrivateKey(const EVPKeyPair & pkey, const std::string & key_type, KeyFormat key_format)
{
    return exportImpl(pkey, key_type, key_format, false);
}

EVPKeyPair importPublicKey(const std::string & key_type, KeyFormat key_format, const ByteRange & key_data)
{
    return importImpl(key_type, key_format, key_data, true);
}

EVPKeyPair importPrivateKey(const std::string & key_type, KeyFormat key_format, const ByteRange & key_data)
{
    return importImpl(key_type, key_format, key_data, false);
}

} // cc7::crypto
} // cc7
