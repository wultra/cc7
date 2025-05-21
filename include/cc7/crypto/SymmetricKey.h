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

#include <cc7/crypto/Key.h>

namespace cc7 {
namespace crypto {

struct SymmetricKeySpec
{
    std::string algorithm;
    size_t key_size;
    
    static const SymmetricKeySpec AES_128;
    static const SymmetricKeySpec AES_192;
    static const SymmetricKeySpec AES_256;
    static const SymmetricKeySpec ANY;
    static const SymmetricKeySpec ANY_128;
    static const SymmetricKeySpec ANY_192;
    static const SymmetricKeySpec ANY_256;
    static const SymmetricKeySpec ANY_384;
    static const SymmetricKeySpec ANY_512;
    
    static const SymmetricKeySpec * specForAlg(const std::string & algorithm);
    static const SymmetricKeySpec * specForSize(const size_t size);
};

class SymmetricKey : public Key
{
public:
    
    size_t getKeySize() const
    {
        return _spec->key_size;
    }
    
    void setKeyData(const ByteRange & key_data)
    {
        if (_spec->key_size && key_data.size() != _spec->key_size) {
            throw std::invalid_argument("Unsupported size of key");
        }
        _key_data = key_data;
    }
    
    const ByteArray & getKeyData() const
    {
        return _key_data;
    }
    
    void setKeyContext(const ByteRange & context)
    {
        _context = context;
    }
    
    const ByteArray & getKeyContext() const
    {
        return _context;
    }
    
    /// Automatic casting to ByteRange.
    operator ByteRange () const
    {
        return _key_data.byteRange();
    }
    
    /// Get instance of symmetric key for specified algorithm and set the key to provided key data.
    /// - Parameters:
    ///   - algorithm: Symmetric key's algorithm.
    ///   - key_data: Key data to set to newly created key.
    static std::shared_ptr<SymmetricKey> getInstance(const std::string & algorithm, const ByteRange & key_data);

    /// Get instance of generic symmetric key and set the key to provided key data.
    /// - Parameter key_data: Key data to set to newly created key.
    static std::shared_ptr<SymmetricKey> getInstance(const ByteRange & key_data);
    
    /// Get instance of symmetric key for specified algorithm.
    ///
    /// The following algorithms are supported:
    /// - "AES-128" - for 128-bit AES keys.
    /// - "AES-192" - for 192-bit AES keys.
    /// - "AES-256" - for 256-bit AES keys.
    /// - "128" - for 128-bit key for unspecified algorithm.
    /// - "192" - for 192-bit key for unspecified algorithm.
    /// - "256" - for 256-bit key for unspecified algorithm.
    /// - "512" - for 512-bit key for unspecified algorithm.
    ///
    /// - Parameter algorithm: Algorithm specification.
    static std::shared_ptr<SymmetricKey> getInstance(const std::string & algorithm);
    
    
    /// Get instance of symmetric key with required length of bytes.
    ///
    /// - Parameter key_size_in_bytes: Size of key in bytes.
    static std::shared_ptr<SymmetricKey> getInstance(size_t key_size_in_bytes);
    
    
    // Key interface
    
    const std::string & getKeyType() const override;
            
    void importKey(const ByteRange & keyData, KeyFormat format = KEY_FORMAT_DEFAULT) override;
    
    ByteArray exportKey(KeyFormat format = KEY_FORMAT_DEFAULT) const override;
    
    Parameter getKeyParameter(int param_id) const override;
    
    void setKeyParameter(int param_id, const Parameter & value) override;
    
    KeyPtr duplicate() const override;
    
private:

    cc7::ByteArray _key_data;
    cc7::ByteArray _context;
    const SymmetricKeySpec * _spec;
    
    SymmetricKey(const SymmetricKeySpec * spec) : _spec(spec) {}
};

typedef std::shared_ptr<SymmetricKey> SymmetricKeyPtr;

} // cc7::crypto
} // cc7
