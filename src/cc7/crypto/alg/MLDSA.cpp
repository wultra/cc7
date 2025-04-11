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

#include "MLDSA.h"
#include "KeyUtility.h"
#include <openssl/x509.h>

namespace cc7
{
namespace crypto
{

// MARK: - MLDSASpec implementation

const MLDSASpec MLDSASpec::ML_DSA_44 = { "ML-DSA-44" };
const MLDSASpec MLDSASpec::ML_DSA_65 = { "ML-DSA-65" };
const MLDSASpec MLDSASpec::ML_DSA_87 = { "ML-DSA-87" };

const MLDSASpec * MLDSASpec::specForAlgorithm(const std::string & algorithm)
{
    if (algorithm == ML_DSA_44.name) {
        return &ML_DSA_44;
    } else if (algorithm == ML_DSA_65.name) {
        return &ML_DSA_65;
    } else if (algorithm == ML_DSA_87.name) {
        return &ML_DSA_87;
    }
    return nullptr;
}



// MARK: - MLDSASignature implementation

std::shared_ptr<MLDSA> MLDSA::getInstance(const std::string & algorithm)
{
    auto spec = MLDSASpec::specForAlgorithm(algorithm);
    if (spec == nullptr) {
        return nullptr;
    }
    return std::shared_ptr<MLDSA>(new MLDSA(spec));
}

// Algorithm interface

const std::string & MLDSA::getAlgorithmName() const
{
    return _spec->name;
}

void MLDSA::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter MLDSA::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

// Signature interface

ByteArray MLDSA::sign(const PrivateKey & private_key, const ByteRange & data) const
{
    const auto& ml_key = checkMLDSAPrivateKey(private_key, algSpec());
    const auto& ll_key = ml_key.getEvpKey();
    
    // TODO: Could we use EVP_PKEY_sign also for ECDSA and unify the algorithms?
    
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_pkey(nullptr, ll_key, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to create context from private key");
    }
    auto sig_alg = EVPSignature::take(EVP_SIGNATURE_fetch(NULL, algName(), NULL));
    if (!sig_alg.isValid()) {
        throw std::domain_error("Failed to fetch signature algorithm");
    }
    // TODO: use params -> https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/#examples
    if (EVP_PKEY_sign_message_init(ctx, sig_alg, nullptr) != 1) {
        throw std::domain_error("Failed to initialize context for data signing");
    }
    size_t sig_length;
    if (EVP_PKEY_sign(ctx, nullptr, &sig_length, data.data(), data.size()) != 1) {
        throw std::domain_error("Failed to estimate output signature length");
    }
    ByteArray signature(sig_length, 0);
    if (EVP_PKEY_sign(ctx, signature.data(), &sig_length, data.data(), data.size()) != 1) {
        throw std::domain_error("Signature calculation failed");
    }
    signature.resize(sig_length);
    return signature;
}

bool MLDSA::verify(const PublicKey & public_key, const ByteRange & signature, const ByteRange & data) const
{
    const auto& ml_key = checkMLDSAPublicKey(public_key, algSpec());
    const auto& ll_key = ml_key.getEvpKey();

    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_pkey(nullptr, ll_key, nullptr));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to create context from public key");
    }
    auto sig_alg = EVPSignature::take(EVP_SIGNATURE_fetch(NULL, algName(), NULL));
    if (!sig_alg.isValid()) {
        throw std::domain_error("Failed to fetch signature algorithm");
    }
    if (EVP_PKEY_verify_message_init(ctx, sig_alg, nullptr) != 1) {
        throw std::domain_error("Failed to initialize context for signature verification");
    }
    auto result = EVP_PKEY_verify(ctx, signature.data(), signature.length(), data.data(), data.length());
    return result == 1;
}


// MARK: - MLDSAKeyPairFactory implementation

KeyPairFactoryPtr MLDSAKeyPairFactory::getInstance(const std::string & key_type)
{
    auto spec = MLDSASpec::specForAlgorithm(key_type);
    if (spec == nullptr) {
        return nullptr;
    }
    return std::make_shared<MLDSAKeyPairFactory>(spec);
}

// KeyPairGenerator interface

KeyPairPtr MLDSAKeyPairFactory::generateKeyPair() const
{
    auto pkey = EVPKeyPair::take(EVP_PKEY_Q_keygen(nullptr, nullptr, algName()));
    if (!pkey.isValid()) {
        throw std::domain_error("Failed to generate ML-DSA key-pair");
    }
    auto pub_key = newPublicKey();
    auto priv_key = newPrivateKey();
    pub_key->importKey(getByteArrayKeyParameter(pkey, OSSL_PKEY_PARAM_PUB_KEY));
    priv_key->importKey(getByteArrayKeyParameter(pkey, OSSL_PKEY_PARAM_PRIV_KEY));
    return std::make_shared<KeyPair>(pub_key, priv_key);
}

PublicKeyPtr MLDSAKeyPairFactory::newPublicKey() const
{
    return PublicKeyPtr(new MLDSAPublicKey(_spec));
}

PrivateKeyPtr MLDSAKeyPairFactory::newPrivateKey() const
{
    return PrivateKeyPtr(new MLDSAPrivateKey(_spec));
}

// Algorithm interface

const std::string & MLDSAKeyPairFactory::getAlgorithmName() const
{
    return _spec->name;
}

void MLDSAKeyPairFactory::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter MLDSAKeyPairFactory::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}


// MARK: - MLDSAPublicKey implementation

const std::string & MLDSAPublicKey::getKeyType() const
{
    return _spec->name;
}

void MLDSAPublicKey::importKey(const ByteRange & keyData, const std::string & format)
{
    EVPKeyPair new_key;
    if (format == KEY_FORMAT_RAW) {
        // RAW key format
        new_key = importRawKey(_spec->name, true, keyData);
    } else if (format == KEY_FORMAT_DER) {
        // DER format
        new_key = importKeyFromDER(_spec->name, true, keyData);
    } else {
        throwUnsupportedKeyConversion(algName(), format);
    }
    getEvpKey() = new_key;
}

ByteArray MLDSAPublicKey::exportKey(const std::string & format) const
{
    if (format == KEY_FORMAT_RAW) {
        return exportKeyToRaw(_ll_key, _spec->name, true);
    } else if (format == KEY_FORMAT_DER) {
        return exportKeyToDER(_ll_key, _spec->name, true);
    }
    throwUnsupportedKeyConversion(algName(), format);
}

std::shared_ptr<Key> MLDSAPublicKey::duplicate() const
{
    if (!_ll_key.isValid()) {
        throwInvalidKey(algName());
    }
    auto duplicated = std::make_shared<MLDSAPublicKey>(algSpec());
    duplicated->importKey(exportKey(KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    return duplicated;

}

Parameter MLDSAPublicKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}


// MARK: - MLDSAPrivateKey implementation

const std::string & MLDSAPrivateKey::getKeyType() const
{
    return _spec->name;
}

void MLDSAPrivateKey::importKey(const ByteRange & keyData, const std::string & format)
{
    EVPKeyPair new_key;
    if (format == KEY_FORMAT_RAW) {
        // RAW key format
        new_key = importRawKey(_spec->name, false, keyData);
    } else if (format == KEY_FORMAT_DER) {
        // DER format
        new_key = importKeyFromDER(_spec->name, false, keyData);
    } else {
        throwUnsupportedKeyConversion(algName(), format);
    }
    getEvpKey() = new_key;
}

ByteArray MLDSAPrivateKey::exportKey(const std::string & format) const
{
    if (format == KEY_FORMAT_RAW) {
        return exportKeyToRaw(_ll_key, _spec->name, false);
    } else if (format == KEY_FORMAT_DER) {
        return exportKeyToDER(_ll_key, _spec->name, false);
    }
    throwUnsupportedKeyConversion(algName(), format);
}

std::shared_ptr<Key> MLDSAPrivateKey::duplicate() const
{
    if (!_ll_key.isValid()) {
        throwInvalidKey(algName());
    }
    auto duplicated = std::make_shared<MLDSAPublicKey>(algSpec());
    duplicated->importKey(exportKey(KEY_FORMAT_DEFAULT), KEY_FORMAT_DEFAULT);
    return duplicated;

}

Parameter MLDSAPrivateKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}



// MARK: - Utils

const MLDSAPublicKey & checkMLDSAPublicKey(const PublicKey & public_key, const MLDSASpec * expected_spec)
{
    auto ml_key = dynamic_cast<const MLDSAPublicKey*>(&public_key);
    if (!ml_key) {
        throw std::invalid_argument("Wrong public key type provided");
    }
    if (!ml_key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty public key type provided");
    }
    if (expected_spec && ml_key->algSpec() != expected_spec) {
        throw std::invalid_argument("Public key with different ML-DSA setup provided");
    }
    return *ml_key;

}

const MLDSAPrivateKey & checkMLDSAPrivateKey(const PrivateKey & private_key, const MLDSASpec * expected_spec)
{
    auto ml_key = dynamic_cast<const MLDSAPrivateKey*>(&private_key);
    if (!ml_key) {
        throw std::invalid_argument("Wrong private key type provided");
    }
    if (!ml_key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty private key type provided");
    }
    if (!EVP_PKEY_can_sign(ml_key->getEvpKey())) {
        throw std::invalid_argument("Provided private key cannot sign data");
    }
    if (expected_spec && ml_key->algSpec() != expected_spec) {
        throw std::invalid_argument("Private key with different ML-DSA setup provided");
    }
    return *ml_key;
}

} // cc7::crypto
} // cc7
