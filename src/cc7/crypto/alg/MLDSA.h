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

namespace cc7
{
namespace crypto
{

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
    virtual const std::string & getKeyType() const;
    virtual void importKey(const ByteRange & keyData, const std::string & format);
    virtual ByteArray exportKey(const std::string & format) const;
    virtual std::shared_ptr<Key> duplicate() const;
    virtual Parameter getKeyParameter(int param_id) const;
    
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
    virtual const std::string & getKeyType() const;
    virtual void importKey(const ByteRange & keyData, const std::string & format);
    virtual ByteArray exportKey(const std::string & format) const;
    virtual std::shared_ptr<Key> duplicate() const;
    virtual Parameter getKeyParameter(int param_id) const;

    const MLDSASpec * algSpec() const { return _spec; }
    const char * algName() const { return _spec->name.c_str(); }
    
    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    MLDSAPrivateKey(const MLDSASpec * spec) :
        _spec(spec)
    {}
    
    MLDSAPrivateKey(EVPKeyPair & ll_key, const MLDSASpec * spec) :
        _spec(spec),
        _ll_key(ll_key)
    {}

private:
    const MLDSASpec * _spec;
    EVPKeyPair  _ll_key;
};


// KeyPairFactory

class MLDSAKeyPairFactory : public KeyPairFactory
{
public:
    // KeyPairFactory interface
    virtual KeyPairPtr generateKeyPair() const;
    virtual PublicKeyPtr newPublicKey() const;
    virtual PrivateKeyPtr newPrivateKey() const;
    // Algorithm interface
    virtual const std::string & getAlgorithmName() const;
    virtual void setParameter(int param_id, const Parameter & value);
    virtual Parameter getParameter(int param_id) const;
    
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
    virtual const std::string & getAlgorithmName() const;
    virtual void setParameter(int param_id, const Parameter & value);
    virtual Parameter getParameter(int param_id) const;
    
    // Signature interface
    virtual ByteArray sign(const PrivateKey & private_key, const ByteRange & data) const;
    virtual bool verify(const PublicKey & public_key, const ByteRange & signature, const ByteRange & data) const;
    
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
