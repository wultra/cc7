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

#include "MLKEM.h"
#include "KeyUtility.h"

namespace cc7
{
namespace crypto
{

// MARK: - MLKEMSpec implementation

const MLKEMSpec MLKEMSpec::ML_KEM_512  = { "ML-KEM-512" };
const MLKEMSpec MLKEMSpec::ML_KEM_768  = { "ML-KEM-768" };
const MLKEMSpec MLKEMSpec::ML_KEM_1024 = { "ML-KEM-1024" };

const MLKEMSpec * MLKEMSpec::specForAlgorithm(const std::string & algorithm)
{
    if (algorithm == ML_KEM_512.name) {
        return &ML_KEM_512;
    } else if (algorithm == ML_KEM_768.name) {
        return &ML_KEM_768;
    } else if (algorithm == ML_KEM_1024.name) {
        return &ML_KEM_1024;
    }
    return nullptr;
}

// MARK: - MLKEMKeyPairFactory

KeyPairFactoryPtr MLKEMKeyPairFactory::getInstance(const std::string & key_type)
{
    auto spec = MLKEMSpec::specForAlgorithm(key_type);
    if (spec == nullptr) {
        return nullptr;
    }
    return std::make_shared<MLKEMKeyPairFactory>(spec);
}


KeyPairPtr MLKEMKeyPairFactory::generateKeyPair() const
{
    auto pkey = EVPKeyPair::take(EVP_PKEY_Q_keygen(ossl_ctx(), nullptr, algName()));
    if (!pkey.isValid()) {
        throw std::domain_error("Failed to generate ML-KEM key-pair");
    }
    auto pub_key = newPublicKey();
    auto priv_key = newPrivateKey();
    pub_key->importKey(exportPublicKey(pkey, algSpec()->name, KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    priv_key->importKey(exportPrivateKey(pkey, algSpec()->name, KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    return std::make_shared<KeyPair>(pub_key, priv_key);
}

PublicKeyPtr MLKEMKeyPairFactory::newPublicKey() const
{
    return std::make_shared<MLKEMPublicKey>(_spec);
}

PrivateKeyPtr MLKEMKeyPairFactory::newPrivateKey() const
{
    return std::make_shared<MLKEMPrivateKey>(_spec);
}

// Algorithm interface

const std::string & MLKEMKeyPairFactory::getAlgorithmName() const
{
    return _spec->name;
}

void MLKEMKeyPairFactory::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter MLKEMKeyPairFactory::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}


// MARK: - MLKEM implementation

std::shared_ptr<MLKEM> MLKEM::getInstance(const std::string & algorithm)
{
    auto spec = MLKEMSpec::specForAlgorithm(algorithm);
    if (spec == nullptr) {
        return nullptr;
    }
    return std::make_shared<MLKEM>(spec);
}

KeyPairPtr MLKEM::generate(const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    return MLKEMKeyPairFactory(_spec).generateKeyPair();
}

SymmetricKeyPtr MLKEM::buildSymmetricKey(const ByteRange & secret) const
{
    if (_output_key_type.empty()) {
        return SymmetricKey::getInstance(secret);
    } else {
        return SymmetricKey::getInstance(_output_key_type, secret);
    }
}

std::pair<ByteArray, SymmetricKeyPtr> MLKEM::encapsulate(const PublicKey & encapsulation_key, const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    
    const auto & ml_key = checkMLKEMPublicKey(encapsulation_key, _spec);
    const auto & ll_key = ml_key.getEvpKey();
    
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_pkey(ossl_ctx(), ll_key, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to create context from public key");
    }
    if (EVP_PKEY_encapsulate_init(ctx, nullptr) != 1) {
        throw std::domain_error("Failed to initialize encapsulation context");
    }
    size_t wrapped_len = 0, secret_len = 0;
    if (EVP_PKEY_encapsulate(ctx, nullptr, &wrapped_len, nullptr, &secret_len) != 1) {
        throw std::domain_error("Failed to determine length of wrapped key");
    }
    ByteArray wrapped(wrapped_len, 0), secret(secret_len, 0);
    if (EVP_PKEY_encapsulate(ctx, wrapped.data(), &wrapped_len, secret.data(), &secret_len) != 1) {
        throw std::domain_error("Failed to encapsulate secret key");
    }
    return std::make_pair(wrapped, buildSymmetricKey(secret));
}

SymmetricKeyPtr MLKEM::decapsulate(const PrivateKey & decapsulation_key, const ByteRange & wrapped_key, const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    
    const auto & ml_key = checkMLKEMPrivateKey(decapsulation_key, _spec);
    const auto & ll_key = ml_key.getEvpKey();
    
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_pkey(ossl_ctx(), ll_key, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to create context from private key");
    }
    if (EVP_PKEY_decapsulate_init(ctx, nullptr) != 1) {
        throw std::domain_error("Failed to initialize decapsulation context");
    }
    size_t secret_len = 0;
    if (EVP_PKEY_decapsulate(ctx, nullptr, &secret_len, wrapped_key.data(), wrapped_key.size()) != 1) {
        throw std::domain_error("Failed to determine length of unwrapped secret");
    }
    ByteArray secret(secret_len, 0);
    if (EVP_PKEY_decapsulate(ctx, secret.data(), &secret_len, wrapped_key.data(), wrapped_key.size()) != 1) {
        throw std::domain_error("Failed to decapsulate secret key");
    }
    return buildSymmetricKey(secret);
}

// Algorithm interface

const std::string & MLKEM::getAlgorithmName() const
{
    return _spec->name;
}

void MLKEM::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case PARAM_OUT_KEY_TYPE:
            _output_key_type = value.asString();
            break;
            
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter MLKEM::getParameter(int param_id) const
{
    switch (param_id) {
        case PARAM_OUT_KEY_TYPE:
            return Parameter::ref(_output_key_type);
            
        default:
            throwUnsupportedParam(param_id);
    }
}


// MARK: MLKEMPublicKey

const std::string & MLKEMPublicKey::getKeyType() const
{
    return _spec->name;
}

void MLKEMPublicKey::importKey(const ByteRange & keyData, KeyFormat format)
{
    getEvpKey() = importPublicKey(_spec->name, format, keyData);
}

ByteArray MLKEMPublicKey::exportKey(KeyFormat format) const
{
    return exportPublicKey(_ll_key, _spec->name, format);
}

std::shared_ptr<Key> MLKEMPublicKey::duplicate() const
{
    auto duplicated = std::make_shared<MLKEMPublicKey>(algSpec());
    if (_ll_key.isValid()) {
        duplicated->importKey(exportKey(KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    }
    return duplicated;
}

Parameter MLKEMPublicKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

void MLKEMPublicKey::setKeyParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}


// MARK: MLKEMPrivateKey

const std::string & MLKEMPrivateKey::getKeyType() const
{
    return _spec->name;
}

void MLKEMPrivateKey::importKey(const ByteRange & keyData, KeyFormat format)
{
    getEvpKey() = importPrivateKey(_spec->name, format, keyData);
}

ByteArray MLKEMPrivateKey::exportKey(KeyFormat format) const
{
    return exportPrivateKey(_ll_key, _spec->name, format);
}

std::shared_ptr<Key> MLKEMPrivateKey::duplicate() const
{
    auto duplicated = std::make_shared<MLKEMPrivateKey>(algSpec());
    if (_ll_key.isValid()) {
        duplicated->importKey(exportKey(KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    }
    return duplicated;
}

Parameter MLKEMPrivateKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

void MLKEMPrivateKey::setKeyParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

// MARK: - Utils

const MLKEMPublicKey & checkMLKEMPublicKey(const PublicKey & public_key, const MLKEMSpec * expected_spec)
{
    auto ml_key = dynamic_cast<const MLKEMPublicKey*>(&public_key);
    if (!ml_key) {
        throw std::invalid_argument("Wrong public key type provided");
    }
    if (!ml_key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty public key type provided");
    }
    if (expected_spec && ml_key->algSpec() != expected_spec) {
        throw std::invalid_argument("Public key with different ML-KEM setup provided");
    }
    return *ml_key;
}

const MLKEMPrivateKey & checkMLKEMPrivateKey(const PrivateKey & private_key, const MLKEMSpec * expected_spec)
{
    auto ml_key = dynamic_cast<const MLKEMPrivateKey*>(&private_key);
    if (!ml_key) {
        throw std::invalid_argument("Wrong private key type provided");
    }
    if (!ml_key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty private key type provided");
    }
    if (expected_spec && ml_key->algSpec() != expected_spec) {
        throw std::invalid_argument("Private key with different ML-KEM setup provided");
    }
    return *ml_key;
}


} // cc7::crypto
} // cc7
