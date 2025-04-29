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

#include <cc7/crypto/KeyPair.h>
#include "../CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

struct ECCurveSpec
{
    std::string name;
    std::string group_name;
    
    static const ECCurveSpec P_256;
    static const ECCurveSpec P_384;
    static const ECCurveSpec P_521;
    
    static const ECCurveSpec * nameToCurveSpec(const std::string & curve_name);
};

// EC Public key

class ECPublicKey : public PublicKey {
public:
    virtual const std::string & getKeyType() const;
    virtual void importKey(const ByteRange & keyData, KeyFormat format);
    virtual ByteArray exportKey(KeyFormat format) const;
    virtual Parameter getKeyParameter(int param_id) const;
    virtual void setKeyParameter(int param_id, const Parameter & value);
    virtual std::shared_ptr<Key> duplicate() const;
    
    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    const ECCurveSpec * curveSpec() const {
        return _curve;
    }
    
    const char * curveName() const {
        return curveSpec()->name.c_str();
    }
    
    ECPublicKey(EVPKeyPair & ll_key, const ECCurveSpec * curve_spec) :
        _ll_key(ll_key),
        _curve(curve_spec)
    {}
    
    ECPublicKey(const ECCurveSpec * curve_spec) :
        _curve(curve_spec)
    {}
    
private:
        
    const ECCurveSpec * _curve;
    EVPKeyPair  _ll_key;
};

// EC Private key

class ECPrivateKey : public PrivateKey {
public:
    virtual const std::string & getKeyType() const;
    virtual void importKey(const ByteRange & keyData, KeyFormat format);
    virtual ByteArray exportKey(KeyFormat format) const;
    virtual Parameter getKeyParameter(int param_id) const;
    virtual void setKeyParameter(int param_id, const Parameter & value);
    virtual std::shared_ptr<Key> duplicate() const;

    const EVPKeyPair & getEvpKey() const {
        return _ll_key;
    }
    
    EVPKeyPair & getEvpKey(){
        return _ll_key;
    }
    
    const ECCurveSpec * curveSpec() const {
        return _curve;
    }
    
    const char * curveName() const {
        return curveSpec()->name.c_str();
    }
    
    ECPrivateKey(EVPKeyPair & ll_key, const ECCurveSpec * curve_spec) :
        _ll_key(ll_key),
        _curve(curve_spec)
    {}

    ECPrivateKey(const ECCurveSpec * curve_spec) :
        _curve(curve_spec)
    {}
    
private:
    const ECCurveSpec * _curve;
    EVPKeyPair  _ll_key;
};

class ECKeyPairFactory : public KeyPairFactory
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
    
    static KeyPairFactoryPtr getInstance(const std::string & algorithm);
    
    ECKeyPairFactory(const ECCurveSpec * spec) : _curve(spec) {}
    
    const ECCurveSpec * algSpec() const { return _curve; }
    const char * algName() const { return _curve->name.c_str(); }
    
private:
    const ECCurveSpec * _curve;
};

// Support functions

const ECPublicKey & checkECPublicKey(const PublicKey & public_key, const ECCurveSpec * expected_curve);
const ECPrivateKey & checkECPrivateKey(const PrivateKey & private_key, const ECCurveSpec * expected_curve, bool check_signing);

} // cc7::crypto
} // cc7
