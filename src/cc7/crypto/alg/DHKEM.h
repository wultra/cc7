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

#include <cc7/crypto/KeyEncapsulation.h>
#include "ECKeyPair.h"
#include "../CryptoPrivate.h"

namespace cc7::crypto {

struct DHKEMSpec
{
    std::string name;
    const ECCurveSpec * curve;
    size_t secretSize;
    
    OSSL_HPKE_SUITE suite;
    
    static const DHKEMSpec * specForAlgorithm(const std::string & algorithm);
};

// PublicKey

class DHKEMPublicKey : public PublicKey
{
public:
    
    // Key interface
    const std::string & getKeyType() const override;
    void importKey(const ByteRange & keyData, KeyFormat format) override;
    ByteArray exportKey(KeyFormat format) const override;
    std::shared_ptr<Key> duplicate() const override;
    Parameter getKeyParameter(int param_id) const override;
    void setKeyParameter(int param_id, const Parameter & value) override;
    
    const DHKEMSpec * algSpec() const { return _spec; }
    
    const ByteArray& getRawKey() const { return _raw_key; }
        
    DHKEMPublicKey(const DHKEMSpec * spec) :
        _spec(spec)
    {}
    
    DHKEMPublicKey(const ByteRange& raw_key, const DHKEMSpec * spec) :
        _spec(spec),
        _raw_key(raw_key)
    {}
    
private:
    const DHKEMSpec * _spec;
    ByteArray _raw_key;
};

// PrivateKey

class DHKEMPrivateKey : public ECPrivateKey
{
public:
    // Key interface
    const std::string & getKeyType() const override;
    std::shared_ptr<Key> duplicate() const override;

    const DHKEMSpec * algSpec() const { return _spec; }

    DHKEMPrivateKey(const DHKEMSpec * spec) :
        ECPrivateKey(spec->curve),
        _spec(spec)
    {}
    
    DHKEMPrivateKey(EVPKeyPair & ll_key, const DHKEMSpec * spec) :
        ECPrivateKey(ll_key, spec->curve),
        _spec(spec)
    {}

private:
    const DHKEMSpec * _spec;
};

// KeyPairFactory

class DHKEMKeyPairFactory : public KeyPairFactory
{
public:
    // KeyPairFactory interface
    KeyPairPtr generateKeyPair() const override;
    PublicKeyPtr newPublicKey() const override;
    PrivateKeyPtr newPrivateKey() const override;
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;
    
    static KeyPairFactoryPtr getInstance(const std::string & key_type);
    
    DHKEMKeyPairFactory(const DHKEMSpec * spec) : _spec(spec) {}

    const DHKEMSpec * algSpec() const { return _spec; }
    
private:
    const DHKEMSpec * _spec;
};

// KeyEncapsulation

class DHKEM : public KeyEncapsulation
{
public:
    
    static std::shared_ptr<DHKEM> getInstance(const std::string & algorithm, KeyDerivationPtr kdf);
    
    // KeyEncapsulation interface
    
    KeyPairPtr generate(const ParameterList & parameters) const override;
    std::pair<ByteArray, SymmetricKeyPtr> encapsulate(const PublicKey & encapsulation_key, const ParameterList & parameters) const override;
    SymmetricKeyPtr decapsulate(const PrivateKey & decapsulation_key, const ByteRange & wrapped_key, const ParameterList & parameters) const override;

    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

    DHKEM(const DHKEMSpec * spec) : _spec(spec), _secret_size(spec->secretSize) {}
    
private:
        
    const DHKEMSpec * _spec;
    
    size_t _secret_size;
    ByteArray _custom_info1;
    ByteArray _custom_info2;
    
    HPKEContext createHpkeContext(bool sender) const;
};

const DHKEMPublicKey & checkDHKEMPublicKey(const PublicKey & public_key, const DHKEMSpec * expected_spec);
const DHKEMPrivateKey & checkDHKEMPrivateKey(const PrivateKey & private_key, const DHKEMSpec * expected_spec);

} // namespace cc7::crypto
