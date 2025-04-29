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
    
    bool   need_padding;
    
    static bool specForAlgorithm(const std::string & algorithm, AESSpec & out_spec);
};

class AES : public Cipher
{
public:
    
    // Cipher
    virtual ByteArray encrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & plaintext) const;
    virtual ByteArray decrypt(const ByteRange & secret_key, const ByteRange & iv, const ByteRange & ciphertext) const;

    // Algorithm
    virtual const std::string & getAlgorithmName() const;
    virtual void setParameter(int param_id, const Parameter & value);
    virtual Parameter getParameter(int param_id) const;

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

} // cc7::crypto
} // cc7
