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

#include <cc7/crypto/Algorithm.h>
#include <set>

namespace cc7 {
namespace crypto {

class NonceGenerator : public BaseObject
{
public:
    virtual size_t getNonceSize() const = 0;
    virtual ByteArray getNonce() = 0;
    virtual bool checkUniqueness(const ByteRange & nonce, bool remember = true) = 0;
    
    virtual ByteArray saveState() const = 0;
    virtual void restoreState(const ByteRange & saved_state) = 0;
    virtual void resetSavedState() = 0;
};

typedef std::shared_ptr<NonceGenerator> NonceGeneratorPtr;


class SimpleNonceGenerator : public NonceGenerator
{
public:
    size_t getNonceSize() const override;
    ByteArray getNonce() override;
    bool checkUniqueness(const ByteRange & nonce, bool remember) override;
    ByteArray saveState() const override;
    void restoreState(const ByteRange & saved_state) override;
    void resetSavedState() override;
    
    static std::shared_ptr<SimpleNonceGenerator> getInstance(size_t nonce_size);
    
    SimpleNonceGenerator(size_t nonce_size);
    
private:
    const size_t _nonce_size;
};


class DefaultNonceGenerator : public NonceGenerator
{
public:
    size_t getNonceSize() const override;
    ByteArray getNonce() override;
    bool checkUniqueness(const ByteRange & nonce, bool remember) override;
    ByteArray saveState() const override;
    void restoreState(const ByteRange & saved_state) override;
    void resetSavedState() override;
    
    static std::shared_ptr<DefaultNonceGenerator> getInstance(size_t nonce_size, size_t bucket_capacity = 64);
    
    DefaultNonceGenerator(size_t nonce_size, size_t bucket_capacity);
    ~DefaultNonceGenerator();
    
private:
    const size_t _nonce_size;
    const size_t _bucket_capacity;
    
    std::set<ByteRange>     _nonce_set;
    std::vector<ByteArray*>  _buckets;
    
    ByteArray & getBucket();
    void clearBuckets();
};

} // cc7::crypto
} // cc7
