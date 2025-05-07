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
#include <cc7/crypto/Algorithm.h>

namespace cc7
{
namespace crypto
{

// Abstract public key interface
class PublicKey : public Key
{
public:
    static std::shared_ptr<PublicKey> getInstance(const std::string & key_type);
};

// Abstract private key interface
class PrivateKey : public Key
{
public:
    static std::shared_ptr<PrivateKey> getInstance(const std::string & key_type);
};

typedef std::shared_ptr<PublicKey> PublicKeyPtr;
typedef std::shared_ptr<PrivateKey> PrivateKeyPtr;


// KeyPair object

class KeyPair : public BaseObject
{
public:
    const PublicKey & getPublicKey() const { return *_public_key; }
    const PrivateKey & getPrivateKey() const { return *_private_key; }
    
    const PublicKeyPtr & getPublicKeyPtr() const { return _public_key; }
    const PrivateKeyPtr & getPrivateKeyPtr() const { return _private_key; }
    
    KeyPair(PublicKeyPtr public_key, PrivateKeyPtr private_key) :
        _public_key(public_key),
        _private_key(private_key)
    {
    }
    
    static std::shared_ptr<KeyPair> generateKeyPair(const std::string & key_type);

private:
    PublicKeyPtr _public_key;
    PrivateKeyPtr _private_key;
};

typedef std::shared_ptr<KeyPair> KeyPairPtr;

// KeyPairFactory

class KeyPairFactory : public Algorithm
{
public:
    virtual KeyPairPtr generateKeyPair() const = 0;
    virtual PublicKeyPtr newPublicKey() const = 0;
    virtual PrivateKeyPtr newPrivateKey() const = 0;
    
    PublicKeyPtr newPublicKey(const ByteRange & key_data, KeyFormat format = KEY_FORMAT_DEFAULT) const
    {
        auto key = newPublicKey();
        key->importKey(key_data, format);
        return key;
    }
    
    PublicKeyPtr newPublicKey(const std::string & key_data, KeyFormat format = KEY_FORMAT_DEFAULT) const
    {
        auto key = newPublicKey();
        key->importKeyFromBase64(key_data, format);
        return key;
    }

    PrivateKeyPtr newPrivateKey(const ByteRange & key_data, KeyFormat format = KEY_FORMAT_DEFAULT) const
    {
        auto key = newPrivateKey();
        key->importKey(key_data, format);
        return key;
    }
    
    PrivateKeyPtr newPrivateKey(const std::string & key_data, KeyFormat format = KEY_FORMAT_DEFAULT) const
    {
        auto key = newPrivateKey();
        key->importKeyFromBase64(key_data, format);
        return key;
    }
    
    static std::shared_ptr<KeyPairFactory> getInstance(const std::string & key_type);
};

typedef std::shared_ptr<KeyPairFactory> KeyPairFactoryPtr;

} // cc7::crypto
} // cc7

