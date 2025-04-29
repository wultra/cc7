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

#include <cc7/crypto/SymmetricKey.h>
#include "CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

// MARK: - SymmetricKey

const std::string & SymmetricKey::getKeyType() const
{
    return _spec->algorithm;
}
        
void SymmetricKey::importKey(const ByteRange & keyData, KeyFormat format)
{
    if (format != KEY_FORMAT_DEFAULT && format != KEY_FORMAT_RAW) {
        throwUnsupportedKeyFormat(getKeyType(), format);
    }
    setKeyData(keyData);
}

ByteArray SymmetricKey::exportKey(KeyFormat format) const
{
    if (format != KEY_FORMAT_DEFAULT && format != KEY_FORMAT_RAW) {
        throwUnsupportedKeyFormat(getKeyType(), format);
    }
    return _key_data;
}

std::shared_ptr<Key> SymmetricKey::duplicate() const
{
    auto copied = new SymmetricKey(_spec);
    if (!_key_data.empty()) {
        copied->setKeyData(_key_data);
    }
    copied->setKeyContext(_context);
    return std::shared_ptr<Key>(copied);
}

Parameter SymmetricKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

void SymmetricKey::setKeyParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}


std::shared_ptr<SymmetricKey> SymmetricKey::getInstance(const std::string & algorithm)
{
    auto spec = SymmetricKeySpec::specForAlg(algorithm);
    if (spec == nullptr) {
        throw std::invalid_argument("Unsupported symmetric key type: " + algorithm);
    }
    return std::shared_ptr<SymmetricKey>(new SymmetricKey(spec));
}

std::shared_ptr<SymmetricKey> SymmetricKey::getInstance(size_t key_size_in_bytes)
{
    auto spec = SymmetricKeySpec::specForSize(key_size_in_bytes);
    if (spec == nullptr) {
        throw std::invalid_argument("Unsupported symmetric key size " + std::to_string(key_size_in_bytes));
    }
    return std::shared_ptr<SymmetricKey>(new SymmetricKey(spec));
}

std::shared_ptr<SymmetricKey> SymmetricKey::getInstance(const std::string & algorithm, const ByteRange & key_data)
{
    auto key = getInstance(algorithm);
    key->setKeyData(key_data);
    return key;
}

std::shared_ptr<SymmetricKey> SymmetricKey::getInstance(const ByteRange & key_data)
{
    auto key = getInstance(key_data.size());
    key->setKeyData(key_data);
    return key;
}


// MARK: - SymmetricKeySpec implementation

const SymmetricKeySpec * SymmetricKeySpec::specForAlg(const std::string & algorithm)
{
    static const std::vector<const SymmetricKeySpec*> spec_list = {
        &AES_128, &AES_192, &AES_256,
        &ANY_128, &ANY_192, &ANY_256, &ANY_384, &ANY_512
    };
    for (auto spec : spec_list) {
        if (spec->algorithm == algorithm) {
            return spec;
        }
    }
    return nullptr;
}

const SymmetricKeySpec * SymmetricKeySpec::specForSize(const size_t size)
{
    switch (size) {
        case 16: return &ANY_128;
        case 24: return &ANY_192;
        case 32: return &ANY_256;
        case 48: return &ANY_384;
        case 64: return &ANY_512;
        default: return &ANY;
    }
}

const SymmetricKeySpec SymmetricKeySpec::AES_128 = { "AES-128", 16 };
const SymmetricKeySpec SymmetricKeySpec::AES_192 = { "AES-192", 24 };
const SymmetricKeySpec SymmetricKeySpec::AES_256 = { "AES-256", 32 };
const SymmetricKeySpec SymmetricKeySpec::ANY_128 = { "GENERIC-128", 16 };
const SymmetricKeySpec SymmetricKeySpec::ANY_192 = { "GENERIC-192", 24 };
const SymmetricKeySpec SymmetricKeySpec::ANY_256 = { "GENERIC-256", 32 };
const SymmetricKeySpec SymmetricKeySpec::ANY_384 = { "GENERIC-384", 48 };
const SymmetricKeySpec SymmetricKeySpec::ANY_512 = { "GENERIC-512", 64 };
const SymmetricKeySpec SymmetricKeySpec::ANY     = { "GENERIC", 0 };

} // cc7::crypto
} // cc7
