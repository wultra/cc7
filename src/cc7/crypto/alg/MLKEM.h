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
#include "../CryptoPrivate.h"

namespace cc7 {
namespace crypto {

struct MLKEMSpec
{
    std::string name;
    
    static const MLKEMSpec * specForAlgorithm(const std::string & algorithm);
    
    static const MLKEMSpec ML_KEM_512;
    static const MLKEMSpec ML_KEM_768;
    static const MLKEMSpec ML_KEM_1024;
};

// PublicKey

class MLKEMPublicKey : public PublicKey
{
public:
    
    // Key interface
    virtual const std::string & getKeyType() const;
    virtual void importKey(const ByteRange & keyData, KeyFormat format);
    virtual ByteArray exportKey(KeyFormat format) const;
    virtual std::shared_ptr<Key> duplicate() const;
    virtual Parameter getKeyParameter(int param_id) const;
    virtual void setKeyParameter(int param_id, const Parameter & value);
    
    const MLKEMSpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    MLKEMPublicKey(const MLKEMSpec * spec) :
        _spec(spec)
    {}
    
    MLKEMPublicKey(EVPKeyPair & ll_key, const MLKEMSpec * spec) :
        _spec(spec),
        _ll_key(ll_key)
    {}
    
private:
    const MLKEMSpec * _spec;
    EVPKeyPair  _ll_key;
};

// PrivateKey

class MLKEMPrivateKey : public PrivateKey
{
public:
    // Key interface
    virtual const std::string & getKeyType() const;
    virtual void importKey(const ByteRange & keyData, KeyFormat format);
    virtual ByteArray exportKey(KeyFormat format) const;
    virtual std::shared_ptr<Key> duplicate() const;
    virtual Parameter getKeyParameter(int param_id) const;
    virtual void setKeyParameter(int param_id, const Parameter & value);

    const MLKEMSpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    MLKEMPrivateKey(const MLKEMSpec * spec) :
        _spec(spec)
    {}
    
    MLKEMPrivateKey(EVPKeyPair & ll_key, const MLKEMSpec * spec) :
        _spec(spec),
        _ll_key(ll_key)
    {}

private:
    const MLKEMSpec * _spec;
    EVPKeyPair  _ll_key;
};


// KeyPairFactory

class MLKEMKeyPairFactory : public KeyPairFactory
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
    
    MLKEMKeyPairFactory(const MLKEMSpec * spec) : _spec(spec) {}

    const MLKEMSpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
private:
    const MLKEMSpec * _spec;
};


// KeyEncapsulation

class MLKEM : public KeyEncapsulation
{
public:
    
    static std::shared_ptr<MLKEM> getInstance(const std::string & algorithm, KeyDerivationPtr kdf);
    
    // KeyEncapsulation interface
    
    KeyPairPtr generate(const ParameterList & parameters) const override;
    std::pair<ByteArray, SymmetricKeyPtr> encapsulate(const PublicKey & encapsulation_key, const ParameterList & parameters) const override;
    SymmetricKeyPtr decapsulate(const PrivateKey & decapsulation_key, const ByteRange & wrapped_key, const ParameterList & parameters) const override;

    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

    MLKEM(const MLKEMSpec * spec, KeyDerivationPtr kdf) : _spec(spec), _kdf(kdf) {}
    
private:
        
    const MLKEMSpec * _spec;
    KeyDerivationPtr _kdf;
    
    SymmetricKeyPtr buildSymmetricKey(const ByteRange & secret) const;
};

const MLKEMPublicKey & checkMLKEMPublicKey(const PublicKey & public_key, const MLKEMSpec * expected_spec);
const MLKEMPrivateKey & checkMLKEMPrivateKey(const PrivateKey & private_key, const MLKEMSpec * expected_spec);

} // cc7::crypto
} // cc7
