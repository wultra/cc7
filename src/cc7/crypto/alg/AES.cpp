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

#include "AES.h"
#include <cc7/crypto/Random.h>
#include <cc7/Utilities.h>

namespace cc7 {
namespace crypto {

// MARK: - AESSpec implementation

struct AESModeSpec
{
    std::string mode;
    size_t iv_size;
    size_t tag_size;
    bool need_padding;
};

static const std::vector<AESModeSpec> s_modes = {
    { "-GCM", 12, 16, false },
    { "-CTR", 16, 0, false },
    { "-CBC", 16, 0, true  },
    { "-ECB", 0, 0, true  },
};

bool AESSpec::specForAlgorithm(const std::string & algorithm, AESSpec & out_spec)
{
    if (stringHasPrefix(algorithm, "AES-128-")) {
        out_spec.key_size = 16;
    } else if (stringHasPrefix(algorithm, "AES-192-")) {
        out_spec.key_size = 24;
    } else if (stringHasPrefix(algorithm, "AES-256-")) {
        out_spec.key_size = 32;
    } else {
        return false;
    }
    
    // lookup for block mode
    auto mode_entry = std::find_if(s_modes.begin(), s_modes.end(), [algorithm](const AESModeSpec & m) {
        return stringHasSuffix(algorithm, m.mode);
    });
    if (mode_entry == s_modes.end()) {
        return false;
    }
    // Success, fill output structure
    out_spec.name         = algorithm;
    out_spec.iv_size      = mode_entry->iv_size;
    out_spec.tag_size     = mode_entry->tag_size;
    out_spec.need_padding = mode_entry->need_padding;
    return true;
}

// MARK: - AES implementation

CipherPtr AES::getInstance(const std::string &algorithm)
{
    AESSpec spec;
    if (!AESSpec::specForAlgorithm(algorithm, spec)) {
        return nullptr;
    }
    auto cipher = EVPCipher::take(EVP_CIPHER_fetch(ossl_ctx(), algorithm.c_str(), nullptr));
    if (!cipher.isValid()) {
        return nullptr;
    }
    return std::shared_ptr<AES>(new AES(spec, cipher));
}

// MARK: Cipher

const std::string & AES::getAlgorithmName() const
{
    return _spec.name;
}

void AES::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case CIPHER_PARAM_USE_PADDING:
            if (!_spec.need_padding) {
                throw std::invalid_argument("Padding is not supported");
            }
            _use_padding = value.asBool();
            break;
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter AES::getParameter(int param_id) const
{
    switch (param_id) {
        case CIPHER_PARAM_IV_LENGTH:
            return Parameter::take(_spec.iv_size);
        case CIPHER_PARAM_TAG_LENGTH:
            return Parameter::take(_spec.tag_size);
        case CIPHER_PARAM_USE_PADDING:
            if (!_spec.need_padding) {
                throw std::invalid_argument("Padding is not supported");
            }
            return Parameter::take(_use_padding);
        default:
            throwUnsupportedParam(param_id);
    }
}


// MARK: Algorithm

ByteArray AES::encrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & plaintext, const ParameterList & parameters) const
{
    auto out_size = validateInputParams(secret_key.size(), iv.size(), plaintext.size(), true);
    auto param_ctx = parameters.beginParameterProcessing();
    ByteArray * out_tag = nullptr;
    ByteRange in_aad;
    if (_spec.tag_size) {
        // Extract pointer to TAG array. This is required for ciphers supporting tag.
        if (!parameters.getOutArray(CIPHER_PARAM_TAG, param_ctx, out_tag)) {
            throw std::invalid_argument("CIPHER_PARAM_TAG is required parameter");
        }
        // AAD is optional
        parameters.getBytes(CIPHER_PARAM_AAD, param_ctx, in_aad);
    }
    parameters.endParameterProcessing(param_ctx);
    
    auto ctx = EVPCipherContext::empty();
    if (EVP_EncryptInit_ex2(ctx, _cipher, secret_key.data(), _spec.iv_size > 0 ? iv.data() : nullptr, nullptr) != 1) {
        throw CryptoException("Failed to initialize encryptor's context");
    }
    if (_spec.need_padding && !_use_padding) {
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
            throw CryptoException("Failed to disable padding");
        }
    }
    int ciphertext_len, len = 0;
    ByteArray out(out_size, 0);
    if (!in_aad.empty()) {
        // Apply input AAD
        if (EVP_EncryptUpdate(ctx, nullptr, &len, in_aad.data(), (int)in_aad.size()) != 1) {
            throw CryptoException("AAD phase failed");
        }
    }
    if (EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), (int)plaintext.size()) != 1) {
        throw CryptoException("Data encryption failed");
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        throw CryptoException("Data encryption finalization failed");
    }
    ciphertext_len += len;
    if (out_size < ciphertext_len) {
        throw CryptoException("AES Fatal error");
    }
    out.resize(ciphertext_len);
    
    if (out_tag) {
        // out tag is present, extract the result
        out_tag->resize(_spec.tag_size);
        OSSL_PARAM get_params[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, out_tag->data(), out_tag->size()),
            OSSL_PARAM_END
        };
        
        if (EVP_CIPHER_CTX_get_params(ctx, get_params) != 1) {
            throw CryptoException("Failed to get TAG");
        }
    }
    return out;
}
    
ByteArray AES::decrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & ciphertext, const ParameterList & parameters) const
{
    auto out_size = validateInputParams(secret_key.size(), iv.size(), ciphertext.size(), false);

    ByteRange in_aad;
    ByteRange in_tag;
    auto param_ctx = parameters.beginParameterProcessing();
    if (_spec.tag_size) {
        // TAG parameter is required
        if (!parameters.getBytes(CIPHER_PARAM_TAG, param_ctx, in_tag)) {
            throw std::invalid_argument("CIPHER_PARAM_TAG is required parameter");
        }
        if (in_tag.size() != _spec.tag_size) {
            throw std::invalid_argument("Invalid TAG size");
        }
        // AAD parameter is optional
        parameters.getBytes(CIPHER_PARAM_AAD, param_ctx, in_aad);
    }
    parameters.endParameterProcessing(param_ctx);
    
    auto ctx = EVPCipherContext::empty();
    if (EVP_DecryptInit_ex2(ctx, _cipher, secret_key.data(), _spec.iv_size > 0 ? iv.data() : nullptr, nullptr) != 1) {
        throw CryptoException("Failed to initialize decryptor's context");
    }
    if (_spec.need_padding && !_use_padding) {
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
            throw CryptoException("Failed to disable padding");
        }
    }
    int plaintext_len, len = 0;
    ByteArray out(out_size, 0);
    if (!in_aad.empty()) {
        // Apply input AAD
        if (EVP_DecryptUpdate(ctx, nullptr, &len, in_aad.data(), (int)in_aad.size()) != 1) {
            throw CryptoException("AAD phase failed");
        }
    }
    if (EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) {
        throw CryptoException("Data decryption failed");
    }
    if (!in_tag.empty()) {
        OSSL_PARAM params[2] = {
            // Unfortunately, OpenSSL cannot create setter with const data pointer.
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, const_cast<uint8_t*>(in_tag.data()), in_tag.size()),
            OSSL_PARAM_END
        };
        if (EVP_CIPHER_CTX_set_params(ctx, params) != 1) {
            throw CryptoException("Failed to set TAG");
        }
    }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        throw CryptoException("Data decryption finalization failed");
    }
    plaintext_len += len;
    out.resize(plaintext_len);
    return out;
}

// MARK: Private functions


size_t AES::validateInputParams(size_t key_size, size_t iv_size, size_t data_size, bool encrypt) const
{
    if (_spec.key_size != key_size) {
        throw std::invalid_argument("Invalid key size");
    }
    if (_spec.iv_size && _spec.iv_size != iv_size) {
        throw std::invalid_argument("Invalid IV size");
    }
    bool not_aligned = (data_size & 0xF) != 0;
    if (encrypt) {
        if (_spec.need_padding && !_use_padding && not_aligned) {
            throw std::invalid_argument("Plaintext is not aligned to block size");
        }
        // encrypt, align data if padding is needed
        if (_spec.need_padding) {
            data_size = utilities::AlignValueUp<16>(data_size);
        }
    } else {
        if (_spec.need_padding && not_aligned) {
            throw std::invalid_argument("Ciphertext is not aligned to block size");
        }
    }
    return data_size;
}




// MARK: - AES_GCM_AEAD

static ByteArray AEAD_I12T16D_Make(const ByteRange & iv, const ByteRange & tag, const ByteRange & ct)
{
    ByteArray out;
    if (iv.size() != 12 || tag.size() != 16) {
        throw InternalError("Invalid IV or TAG size in AEAD");
    }
    out.reserve(ct.size() + 12 + 16);
    out.assign(iv);
    out.append(tag);
    out.append(ct);
    return out;
}

static void AEAD_I12T16D_Extract(const ByteRange & cryptogram, ByteRange & iv, ByteRange & tag, ByteRange & ct)
{
    if (cryptogram.size() < 12 + 16) {
        throw std::invalid_argument("AEAD crytogram is too short");
    }
    iv  = cryptogram.subRangeTo(12);
    tag = cryptogram.subRange(12, 16);
    ct  = cryptogram.subRangeFrom(12 + 16);
}


const AES_AEAD_Spec * AES_AEAD_Spec::specForAlgorithm(const std::string & algorithm)
{
    static const std::vector<AES_AEAD_Spec> spec_list {
        { "AES-128-GCM#I12T16D", "AES-128-GCM", AEAD_I12T16D_Make, AEAD_I12T16D_Extract },
        { "AES-192-GCM#I12T16D", "AES-192-GCM", AEAD_I12T16D_Make, AEAD_I12T16D_Extract },
        { "AES-256-GCM#I12T16D", "AES-256-GCM", AEAD_I12T16D_Make, AEAD_I12T16D_Extract },
    };
    for (const auto & spec : spec_list) {
        if (spec.name == algorithm) {
            return &spec;
        }
    }
    return nullptr;
}

AEADPtr AES_GCM_AEAD::getInstance(const std::string &algorithm)
{
    const auto spec = AES_AEAD_Spec::specForAlgorithm(algorithm);
    if (!spec) {
        return nullptr;
    }
    auto cipher = AES::getInstance(spec->cipher);
    if (cipher == nullptr) {
        throw InternalError("Broken AES_AEAD_Spec table");
    }
    return std::make_shared<AES_GCM_AEAD>(spec, cipher);
}

// AEAD interface
ByteArray AES_GCM_AEAD::seal(const ByteRange & key, const ByteRange & nonce, const ByteRange & associated_data, const ByteRange & plaintext, const ParameterList & params) const
{
    auto nonce_generator = _nonce_generator;
    auto param_ctx = params.beginParameterProcessing();
    if (params.getTypedObject<NonceGenerator>(AEAD_NONCE_GENERATOR, param_ctx, nonce_generator)) {
        if (nonce_generator->getNonceSize() != 12) {
            throw std::invalid_argument("Nonce generator generates nonce with wrong size");
        }
    }
    params.endParameterProcessing(param_ctx);
    
    ByteArray iv = nonce;
    if (iv.empty()) {
        if (nonce_generator != nullptr) {
            iv = nonce_generator->getNonce();
        } else {
            iv = GetRandomData(12, true);
        }
    }
    ByteArray tag;
    auto ct = _aes->encrypt(key, iv, plaintext, {
        { CIPHER_PARAM_TAG, Parameter::outRef(tag) },
        { CIPHER_PARAM_AAD, Parameter::ref(associated_data) }
    });
    return _spec->MakeCryptogram(iv, tag, ct);
}

ByteArray AES_GCM_AEAD::open(const ByteRange & key, const ByteRange & associated_data, const ByteRange & ciphertext, const ParameterList & params) const
{
    params.throwUnsupported();
    
    ByteRange iv, tag, ct;
    _spec->ExtractFields(ciphertext, iv, tag, ct);
    return _aes->decrypt(key, iv, ct, {
        { CIPHER_PARAM_TAG, Parameter::ref(tag) },
        { CIPHER_PARAM_AAD, Parameter::ref(associated_data) }
    });
}

ByteArray AES_GCM_AEAD::extractNonce(const ByteRange & ciphertext) const
{
    ByteRange iv, tag, ct;
    _spec->ExtractFields(ciphertext, iv, tag, ct);
    return iv;
}

// Algorithm interface
const std::string & AES_GCM_AEAD::getAlgorithmName() const
{
    return _spec->name;
}

void AES_GCM_AEAD::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case AEAD_NONCE_GENERATOR: {
            auto generator = std::dynamic_pointer_cast<NonceGenerator>(value.asObject());
            if (generator && generator->getNonceSize() != 12) {
                throw std::invalid_argument("Nonce generator generates nonce with wrong size");
            }
            _nonce_generator = generator;
            break;
        }
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter AES_GCM_AEAD::getParameter(int param_id) const
{
    switch (param_id) {
        case AEAD_NONCE_GENERATOR:
            return Parameter::take(_nonce_generator);
            
        default:
            throwUnsupportedParam(param_id);
    }
}

} // cc7::crypto
} // cc7
