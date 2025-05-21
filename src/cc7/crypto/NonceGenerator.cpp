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
}

size_t SimpleNonceGenerator::getNonceSize() const
{
    return _nonce_size;
}

ByteArray SimpleNonceGenerator::getNonce()
{
    return GetRandomData(_nonce_size, true);
}

bool SimpleNonceGenerator::checkUniqueness(const ByteRange & nonce, bool remember)
{
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

std::shared_ptr<DefaultNonceGenerator> DefaultNonceGenerator::getInstance(size_t nonce_size, size_t bucket_capacity)
{
    return std::make_shared<DefaultNonceGenerator>(nonce_size, bucket_capacity);
}

DefaultNonceGenerator::DefaultNonceGenerator(size_t nonce_size, size_t bucket_capacity) :
    _nonce_size(nonce_size),
    _bucket_capacity(bucket_capacity)
{
}

DefaultNonceGenerator::~DefaultNonceGenerator()
{
    clearBuckets();
}

size_t DefaultNonceGenerator::getNonceSize() const
{
    return _nonce_size;
}

ByteArray DefaultNonceGenerator::getNonce()
{
    ByteArray nonce(_nonce_size, 0);
    int attempts = 16;
    while (attempts-- > 0) {
        nonce = GetRandomData(_nonce_size);
        if (checkUniqueness(nonce, true)) {
            return nonce;
        }
    }
    throw CryptoException("Failed to generate unique nonce");
}

bool DefaultNonceGenerator::checkUniqueness(const ByteRange & nonce, bool remember)
{
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
    auto bucket_size = _nonce_size * _bucket_capacity;
    if (_buckets.empty() || _buckets.back()->size() == bucket_size) {
        // No buckets allocated, or top bucket is full
        auto bucket = new ByteArray();
        bucket->reserve(bucket_size);
        _buckets.push_back(bucket);
    }
    return *_buckets.back();
}

void DefaultNonceGenerator::clearBuckets()
{
    for (auto ptr : _buckets) {
        delete ptr;
    }
    _buckets.clear();
    _nonce_set.clear();
}

} // cc7::crypto
} // cc74
