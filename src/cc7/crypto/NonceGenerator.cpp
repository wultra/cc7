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

#include <cc7/crypto/NonceGenerator.h>
#include <cc7/crypto/Random.h>

namespace cc7 {
namespace crypto {

// MARK: - SimpleNonceGenerator

std::shared_ptr<SimpleNonceGenerator> SimpleNonceGenerator::getInstance(size_t nonce_size)
{
    return std::make_shared<SimpleNonceGenerator>(nonce_size);
}

SimpleNonceGenerator::SimpleNonceGenerator(size_t nonce_size) :
    _nonce_size(nonce_size)
{
    if (_nonce_size == 0) {
        throw std::invalid_argument("Invalid nonce_size parameter");
    }
}

size_t SimpleNonceGenerator::getNonceSize() const noexcept
{
    return _nonce_size;
}

ByteArray SimpleNonceGenerator::getNonce()
{
    return GetRandomData(_nonce_size, true);
}

bool SimpleNonceGenerator::checkUniqueness(const ByteRange & nonce, bool remember)
{
    if (nonce.size() != _nonce_size) {
        throw std::invalid_argument("Wrong size of nonce");
    }
    return true;
}

ByteArray SimpleNonceGenerator::saveState() const
{
    return ByteArray();
}

void SimpleNonceGenerator::restoreState(const ByteRange & saved_state)
{
    // Do nothing
}

void SimpleNonceGenerator::resetSavedState()
{
    // Do nothing
}


// MARK: - DefaultNonceGenerator

const DefaultNonceGenerator::Configuration DefaultNonceGenerator::DEFAULT_CONFIG = { 64, 16 };

std::shared_ptr<DefaultNonceGenerator> DefaultNonceGenerator::getInstance(size_t nonce_size,
                                                                          const Configuration& configuration)
{
    return std::make_shared<DefaultNonceGenerator>(nonce_size, configuration);
}

DefaultNonceGenerator::DefaultNonceGenerator(size_t nonce_size, const Configuration& configuration) :
    _nonce_size(nonce_size),
    _config(configuration)
{
    if (_nonce_size == 0) {
        throw std::invalid_argument("Invalid nonce_size parameter");
    }
    if (_config.bucketCapacity == 0) {
        throw std::invalid_argument("Invalid configuration.bucketCapacity parameter");
    }
    if (_config.attempts == 0) {
        throw std::invalid_argument("Invalid configuration.attempts parameter");
    }
}

const DefaultNonceGenerator::Configuration& DefaultNonceGenerator::getConfiguration() const noexcept
{
    return _config;
}

size_t DefaultNonceGenerator::getNonceSize() const noexcept
{
    return _nonce_size;
}

ByteArray DefaultNonceGenerator::getNonce()
{
    ByteArray nonce(_nonce_size, 0);
    auto attempts = _config.attempts;
    do {
        nonce = GetRandomData(_nonce_size);
        if (checkUniqueness(nonce, true)) {
            return nonce;
        }
        --attempts;
    } while (attempts != 0);
    throw CryptoException("Failed to generate unique nonce");
}

bool DefaultNonceGenerator::checkUniqueness(const ByteRange & nonce, bool remember)
{
    if (nonce.size() != _nonce_size) {
        throw std::invalid_argument("Wrong size of nonce");
    }
    if (_nonce_set.find(nonce) != _nonce_set.end()) {
        return false;  // Not unique
    }
    if (remember) {
        auto& bucket = getBucket();
        auto start = bucket.size();
        bucket.append(nonce);
        auto new_range = bucket.byteRange().subRange(start, _nonce_size);
        _nonce_set.insert(new_range);
    }
    return true;
}

struct Header
{
    char magic[8];
    size_t nonce_size;
    size_t nonce_count;
};

ByteArray DefaultNonceGenerator::saveState() const
{
    ByteArray out;
    auto expected_size = sizeof(Header) + _nonce_set.size() * _nonce_size;
    out.reserve(expected_size);
    Header hdr {
        { 'N', 'O', 'G', '1', 0, 0, 0, 0 },
        _nonce_size,
        _nonce_set.size()
    };
    out.append(MakeRange(hdr));
    for (const auto & nonce : _nonce_set) {
        out.append(nonce);
    }
    if (out.size() != expected_size) {
        throw InternalError("Unexpected output size");
    }
    return out;
}

void DefaultNonceGenerator::restoreState(const ByteRange & saved_state)
{
    size_t ptr = 0;
    if (saved_state.size() < sizeof(Header)) {
        throw std::invalid_argument("Wrong header");
    }
    const auto header = (const Header*)(saved_state.subRangeTo(sizeof(Header)).data());
    if (header->magic[0] != 'N' || header->magic[1] != 'O' || header->magic[2] != 'G' || header->magic[3] != '1') {
        throw std::invalid_argument("Wrong header");
    }
    if (header->nonce_size != _nonce_size) {
        throw std::invalid_argument("Wrong nonce size");
    }
    if (header->nonce_size * header->nonce_count + sizeof(Header) != saved_state.size()) {
        throw std::invalid_argument("Wrong saved data size");
    }
    
    clearBuckets();
    ptr += sizeof(Header);
    // Import all nonces
    for (size_t i = 0; i < header->nonce_count; i++) {
        auto nonce = saved_state.subRange(ptr, _nonce_size);
        if (!checkUniqueness(nonce, true)) {
            throw std::invalid_argument("Saved nonce is not unique");
        }
        ptr += _nonce_size;
    }
}

void DefaultNonceGenerator::resetSavedState()
{
    clearBuckets();
    getBucket();
}

ByteArray& DefaultNonceGenerator::getBucket()
{
    auto bucket_size = _nonce_size * _config.bucketCapacity;
    if (_buckets.empty() || _buckets.back()->size() == bucket_size) {
        // No buckets allocated, or top bucket is full
        auto bucket = std::make_unique<ByteArray>();
        bucket->reserve(bucket_size);
        _buckets.push_back(std::move(bucket));
    }
    return *_buckets.back();
}

void DefaultNonceGenerator::clearBuckets()
{
    _buckets.clear();
    _nonce_set.clear();
}


// MARK: - CollisionResistantNonceGenerator

CollisionResistantNonceGenerator::CollisionResistantNonceGenerator(size_t nonce_size,
                                                                   size_t derived_key_size,
                                                                   const KeyDerivationPtr& kdf,
                                                                   const Configuration& configuration) :
    _nonce_size(nonce_size),
    _derived_key_size(derived_key_size),
    _kdf(kdf),
    _key_validator(derived_key_size, configuration)
{
    if (!_kdf) {
        throw std::invalid_argument("KDF function is required");
    }
    _kdf->setParameter(KDF_PARAM_KEY_SIZE, Parameter::take(derived_key_size));
}

std::shared_ptr<CollisionResistantNonceGenerator> CollisionResistantNonceGenerator::getInstance(size_t nonce_size,
                                                                                                size_t derived_key_size,
                                                                                                const KeyDerivationPtr& kdf,
                                                                                                const Configuration& configuration)
{
    return std::make_shared<CollisionResistantNonceGenerator>(nonce_size, derived_key_size, kdf, configuration);
}

const KeyDerivation& CollisionResistantNonceGenerator::getKeyDerivation() const noexcept
{
    return *_kdf;
}

KeyDerivation& CollisionResistantNonceGenerator::getKeyDerivation() noexcept
{
    return *_kdf;
}

size_t CollisionResistantNonceGenerator::getNonceSize() const noexcept
{
    return _nonce_size;
}

const CollisionResistantNonceGenerator::Configuration& CollisionResistantNonceGenerator::getConfiguration() const noexcept
{
    return _key_validator.getConfiguration();
}

ByteArray CollisionResistantNonceGenerator::getNonce()
{
    ByteArray nonce(_nonce_size, 0);
    ByteArray key(_derived_key_size, 0);
    auto attempts = getConfiguration().attempts;
    do {
        nonce = GetRandomData(_nonce_size);
        key = deriveKeyFromNonce(nonce);
        if (_key_validator.checkUniqueness(key, true)) {
            return nonce;
        }
        attempts--;
    } while (attempts != 0);
    throw CryptoException("Failed to generate unique nonce");
}

bool CollisionResistantNonceGenerator::checkUniqueness(const ByteRange & nonce, bool remember)
{
    if (nonce.size() != _nonce_size) {
        throw std::invalid_argument("Wrong size of nonce");
    }
    auto key = deriveKeyFromNonce(nonce);
    return _key_validator.checkUniqueness(key, remember);
}

ByteArray CollisionResistantNonceGenerator::saveState() const
{
    return _key_validator.saveState();
}

void CollisionResistantNonceGenerator::restoreState(const ByteRange & saved_state)
{
    _key_validator.restoreState(saved_state);
}

void CollisionResistantNonceGenerator::resetSavedState()
{
    _key_validator.resetSavedState();
}

ByteArray CollisionResistantNonceGenerator::deriveKeyFromNonce(const ByteRange& nonce) const
{
    auto key = _kdf->deriveKeyBytes(nonce);
    if (key.size() != _derived_key_size) {
        throw CryptoException("KDF function returned unexpected key size");
    }
    return key;
}

} // cc7::crypto
} // cc74
