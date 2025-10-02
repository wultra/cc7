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

#include <cc7/crypto/Signature.h>
#include "../CryptoPrivate.h"

namespace cc7 {
namespace crypto {

// Common specification

struct MLDSASpec
{
    std::string name;
    
    static const MLDSASpec * specForAlgorithm(const std::string & algorithm);
    
    static const MLDSASpec ML_DSA_44;
    static const MLDSASpec ML_DSA_65;
    static const MLDSASpec ML_DSA_87;
};

// PublicKey

class MLDSAPublicKey : public PublicKey
{
public:
    // Key interface
    const std::string & getKeyType() const override;
    void importKey(const ByteRange & keyData, KeyFormat format) override;
    ByteArray exportKey(KeyFormat format) const override;
    std::shared_ptr<Key> duplicate() const override;
    Parameter getKeyParameter(int param_id) const override;
    void setKeyParameter(int param_id, const Parameter & value) override;
    
    const MLDSASpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    MLDSAPublicKey(const MLDSASpec * spec) :
        _spec(spec)
    {}
    
    MLDSAPublicKey(EVPKeyPair & ll_key, const MLDSASpec * spec) :
        _spec(spec),
        _ll_key(ll_key)
    {}
    
private:
    const MLDSASpec * _spec;
    EVPKeyPair  _ll_key;
};


// PrivateKey

class MLDSAPrivateKey : public PrivateKey
{
public:
    // Key interface
    const std::string & getKeyType() const override;
    void importKey(const ByteRange & keyData, KeyFormat format) override;
    ByteArray exportKey(KeyFormat format) const override;
    std::shared_ptr<Key> duplicate() const override;
    Parameter getKeyParameter(int param_id) const override;
    void setKeyParameter(int param_id, const Parameter & value) override;
    // PrivateKey interface
    bool isSealed() const noexcept override;
    void setSealed() noexcept override;

    const MLDSASpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    MLDSAPrivateKey(const MLDSASpec * spec) :
        _spec(spec),
        _sealed(false)
    {}
    
    MLDSAPrivateKey(EVPKeyPair & ll_key, const MLDSASpec * spec) :
        _spec(spec),
        _ll_key(ll_key),
        _sealed(false)
    {}

private:
    void checkNotSealed() const;
    
    const MLDSASpec * _spec;
    EVPKeyPair  _ll_key;
    bool _sealed;
};


// KeyPairFactory

class MLDSAKeyPairFactory : public KeyPairFactory
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
    
    MLDSAKeyPairFactory(const MLDSASpec * spec) : _spec(spec) {}

    const MLDSASpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
private:
    const MLDSASpec * _spec;
};


// Signature

class MLDSA : public Signature
{
public:
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;
    
    // Signature interface
    ByteArray sign(const PrivateKey & private_key, const ByteRange & data, const ParameterList & parameters) const override;
    bool verify(const PublicKey & public_key, const ByteRange & signature, const ByteRange & data, const ParameterList & parameters) const override;
    
    static std::shared_ptr<MLDSA> getInstance(const std::string & algorithm);
    
    const MLDSASpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
private:
    
    MLDSA(const MLDSASpec * spec) : _spec(spec) {}
    
    const MLDSASpec * _spec;
};

// Utils

const MLDSAPublicKey & checkMLDSAPublicKey(const PublicKey & public_key, const MLDSASpec * expected_spec);
const MLDSAPrivateKey & checkMLDSAPrivateKey(const PrivateKey & private_key, const MLDSASpec * expected_spec);
    
} // cc7::crypto
} // cc7
