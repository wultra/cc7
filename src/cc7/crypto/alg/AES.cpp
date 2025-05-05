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
#include <cc7/Utilities.h>

namespace cc7
{
namespace crypto
{

// MARK: - AESSpec implementation

struct AESModeSpec
{
    std::string mode;
    size_t iv_size;
    bool   need_padding;
};

static const std::vector<AESModeSpec> s_modes = {
    { "-CTR", 16, false },
    { "-CBC", 16, true  },
    { "-ECB", 0, true  },
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
    parameters.throwUnsupported();
    
    auto ctx = EVPCipherContext::empty();
    if (EVP_EncryptInit_ex2(ctx, _cipher, secret_key.data(), _spec.iv_size > 0 ? iv.data() : nullptr, nullptr) != 1) {
        throw std::domain_error("Failed to initialize encryptor's context");
    }
    if (!_use_padding && EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        throw std::domain_error("Failed to disable padding");
    }
    
    int ciphertext_len, len = 0;
    ByteArray out(out_size, 0);
    if (EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), (int)plaintext.size()) != 1) {
        throw std::domain_error("Data encryption failed");
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        throw std::domain_error("Data encryption finalization failed");
    }
    ciphertext_len += len;
    if (out_size < ciphertext_len) {
        throw std::domain_error("Fatal error");
    }
    out.resize(ciphertext_len);
    return out;
}
    
ByteArray AES::decrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & ciphertext, const ParameterList & parameters) const
{
    auto out_size = validateInputParams(secret_key.size(), iv.size(), ciphertext.size(), false);
    parameters.throwUnsupported();
    
    auto ctx = EVPCipherContext::empty();
    if (EVP_DecryptInit_ex2(ctx, _cipher, secret_key.data(), _spec.iv_size > 0 ? iv.data() : nullptr, nullptr) != 1) {
        throw std::domain_error("Failed to initialize decryptor's context");
    }
    if (!_use_padding && EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        throw std::domain_error("Failed to disable padding");
    }
    int plaintext_len, len = 0;
    ByteArray out(out_size, 0);
    if (EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) {
        throw std::domain_error("Data decryption failed");
    }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        throw std::domain_error("Data decryption finalization failed");
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

} // cc7::crypto
} // cc7
