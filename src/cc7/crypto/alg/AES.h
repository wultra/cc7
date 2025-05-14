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

#include <cc7/crypto/Cipher.h>
#include <cc7/crypto/AEAD.h>
#include "../CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

struct AESSpec
{
    std::string name;
    
    size_t key_size;
    size_t iv_size;
    size_t tag_size;
    
    bool   need_padding;
    
    static bool specForAlgorithm(const std::string & algorithm, AESSpec & out_spec);
};

class AES : public Cipher
{
public:
    
    // Cipher
    ByteArray encrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & plaintext, const ParameterList & parameters) const override;
    ByteArray decrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & ciphertext, const ParameterList & parameters) const override;

    // Algorithm
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

    static CipherPtr getInstance(const std::string & algorithm);
    
    
private:
    const AESSpec _spec;
    EVPCipher _cipher;
    bool _use_padding;
    
    AES(const AESSpec & spec, EVPCipher & cipher) :
        _spec(spec),
        _cipher(cipher),
        _use_padding(spec.need_padding)
    {}
    
    size_t validateInputParams(size_t key_size, size_t iv_size, size_t data_size, bool encrypt) const;
};


struct AES_AEAD_Spec
{
    std::string name;
    std::string cipher;
    ByteArray (*MakeCryptogram)(const ByteRange & iv, const ByteRange & tag, const ByteRange & ct);
    void      (*ExtractFields)(const ByteRange & cryptogram, ByteRange & iv, ByteRange & tag, ByteRange & ct);
    
    static const AES_AEAD_Spec * specForAlgorithm(const std::string & algorithm);
};

class AES_GCM_AEAD : public AEAD
{
public:
    // AEAD interface
    ByteArray seal(const ByteRange & key,
                   const ByteRange & nonce,
                   const ByteRange & associated_data,
                   const ByteRange & plaintext,
                   const ParameterList & params) const override;
    
    ByteArray open(const ByteRange & key,
                   const ByteRange & associated_data,
                   const ByteRange & ciphertext,
                   const ParameterList & params) const override;
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

    AES_GCM_AEAD(const AES_AEAD_Spec * spec, CipherPtr cipher) : _spec(spec), _aes(cipher) {}
    
    static AEADPtr getInstance(const std::string & algorithm);

private:
    const AES_AEAD_Spec * _spec;
    CipherPtr _aes;
};

} // cc7::crypto
} // cc7
