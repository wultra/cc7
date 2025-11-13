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

#include "DHKEM.h"
#include "NullKDF.h"
#include "KeyUtility.h"

namespace cc7 {
namespace crypto {


#define MAX_PUB_LEN 256
#define MAX_ENC_LEN 256

// MARK: - DHKEMSpec

static const DHKEMSpec spec_P256_HKDF_SHA256 {
    "DHKEM-P256-HKDF-SHA256", &ECCurveSpec::P_256, 32,
    {
        .kem_id = OSSL_HPKE_KEM_ID_P256,
        .kdf_id = OSSL_HPKE_KDF_ID_HKDF_SHA256,
        .aead_id = OSSL_HPKE_AEAD_ID_EXPORTONLY
    }
};

static const DHKEMSpec spec_P384_HKDF_SHA384 {
    "DHKEM-P384-HKDF-SHA384", &ECCurveSpec::P_384, 48,
    {
        .kem_id = OSSL_HPKE_KEM_ID_P384,
        .kdf_id = OSSL_HPKE_KDF_ID_HKDF_SHA384,
        .aead_id = OSSL_HPKE_AEAD_ID_EXPORTONLY
    }
};

static const DHKEMSpec spec_P521_HKDF_SHA512 {
    "DHKEM-P521-HKDF-SHA512", &ECCurveSpec::P_521, 64,
    {
        .kem_id = OSSL_HPKE_KEM_ID_P521,
        .kdf_id = OSSL_HPKE_KDF_ID_HKDF_SHA512,
        .aead_id = OSSL_HPKE_AEAD_ID_EXPORTONLY
    }
};

const DHKEMSpec* DHKEMSpec::specForAlgorithm(const std::string &algorithm)
{
    if (algorithm == spec_P256_HKDF_SHA256.name) {
        return &spec_P256_HKDF_SHA256;
    }
    if (algorithm == spec_P384_HKDF_SHA384.name) {
        return &spec_P384_HKDF_SHA384;
    }
    if (algorithm == spec_P521_HKDF_SHA512.name) {
        return &spec_P521_HKDF_SHA512;
    }
    return nullptr;
}

// MARK: - DHKEMPublicKey

const std::string& DHKEMPublicKey::getKeyType() const
{
    return _spec->name;
}

void DHKEMPublicKey::importKey(const ByteRange &keyData, KeyFormat format)
{
    if (format != KEY_FORMAT_DEFAULT && format != KEY_FORMAT_RAW) {
        throwUnsupportedKeyFormat(_spec->name, format);
    }
    // validate EC key
    importPublicKey(_spec->curve->name, KEY_FORMAT_RAW, keyData);
    _raw_key = keyData;
}

ByteArray DHKEMPublicKey::exportKey(KeyFormat format) const
{
    if (format != KEY_FORMAT_DEFAULT && format != KEY_FORMAT_RAW) {
        throwUnsupportedKeyFormat(_spec->name, format);
    }
    if (_raw_key.empty()) {
        throwInvalidKey(_spec->name);
    }
    return _raw_key;
}

std::shared_ptr<Key> DHKEMPublicKey::duplicate() const
{
    return std::make_shared<DHKEMPublicKey>(_raw_key, _spec);
}

Parameter DHKEMPublicKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

void DHKEMPublicKey::setKeyParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}


// MARK: - DHKEMPrivateKey

const std::string & DHKEMPrivateKey::getKeyType() const
{
    return _spec->name;
}

std::shared_ptr<Key> DHKEMPrivateKey::duplicate() const
{
    auto duplicated = std::make_shared<DHKEMPrivateKey>(_spec);
    if (getEvpKey().isValid()) {
        duplicated->importKey(exportKey(KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    }
    return duplicated;
}

// MARK: - DHKEMKeyPairFactory

KeyPairPtr DHKEMKeyPairFactory::generateKeyPair() const
{
    byte   pub_data[MAX_PUB_LEN];
    size_t pub_data_len = sizeof(pub_data);
    EVPKeyPair priv_key;
    if (OSSL_HPKE_keygen(_spec->suite, pub_data, &pub_data_len, priv_key.objectRef(),
                         nullptr, 0, ossl_ctx(), nullptr) != 1) {
        throw CryptoException("Failed to generate DH-KEM key-pair");
    }
    auto public_key  = std::make_shared<DHKEMPublicKey>(ByteRange(pub_data, pub_data_len), _spec);
    auto private_key = std::make_shared<DHKEMPrivateKey>(priv_key, _spec);
    return std::make_shared<KeyPair>(public_key, private_key);
}

PublicKeyPtr DHKEMKeyPairFactory::newPublicKey() const
{
    return std::make_shared<DHKEMPublicKey>(_spec);
}

PrivateKeyPtr DHKEMKeyPairFactory::newPrivateKey() const
{
    return std::make_shared<DHKEMPrivateKey>(_spec);
}

const std::string & DHKEMKeyPairFactory::getAlgorithmName() const
{
    return _spec->name;
}

void DHKEMKeyPairFactory::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter DHKEMKeyPairFactory::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

KeyPairFactoryPtr DHKEMKeyPairFactory::getInstance(const std::string & key_type)
{
    auto spec = DHKEMSpec::specForAlgorithm(key_type);
    if (spec == nullptr) {
        return nullptr;
    }
    return std::make_shared<DHKEMKeyPairFactory>(spec);
}


// MARK: - DHKEM

std::shared_ptr<DHKEM> DHKEM::getInstance(const std::string & algorithm, KeyDerivationPtr kdf)
{
    if (kdf != nullptr) {
        if (!std::dynamic_pointer_cast<NullKDF>(kdf)) {
            // If cast failed, then this is custom KDF
            throw std::invalid_argument("DHKEM doesn't support custom KDF function");
        }
    }
    auto spec = DHKEMSpec::specForAlgorithm(algorithm);
    if (spec == nullptr) {
        return nullptr;
    }
    return std::make_shared<DHKEM>(spec);
}

KeyPairPtr DHKEM::generate(const ParameterList & parameters) const
{
    parameters.throwUnsupported();
    return DHKEMKeyPairFactory(_spec).generateKeyPair();
}

std::pair<ByteArray, SymmetricKeyPtr> DHKEM::encapsulate(const PublicKey & encapsulation_key, const ParameterList & parameters) const
{
    // Validate input key
    const auto& pub_key = checkDHKEMPublicKey(encapsulation_key, _spec);
    
    // Customization
    auto info = _custom_info.byteRange();
    auto secret_size = _secret_size;

    // Validate parameters
    auto param_ctx = parameters.beginParameterProcessing();
    parameters.getBytes(KEY_ENCAPSULATION_PARAM_INFO, param_ctx, info);
    parameters.getSize(KEY_ENCAPSULATION_PARAM_SECRET_SIZE, param_ctx, secret_size);
    parameters.endParameterProcessing(param_ctx);
    
    // Encapsulate
    auto ctx = createHpkeContext(true);
    byte enc_buffer[MAX_ENC_LEN];
    size_t enc_buffer_len = sizeof(enc_buffer);
    
    if (OSSL_HPKE_encap(ctx,
                        enc_buffer, &enc_buffer_len,
                        pub_key.getRawKey().data(), pub_key.getRawKey().size(),
                        nullptr, 0) != 1) {
        throw CryptoException("Failed to encapsulate secret key");
    }
    
    // Export
    auto secret = ByteArray(secret_size, 0);
    if (OSSL_HPKE_export(ctx, secret.data(), secret.size(), info.data(), info.size()) != 1) {
        throw CryptoException("Failed to export secret key");
    }
    
    // Return result pair
    return std::make_pair(ByteArray(ByteRange(enc_buffer, enc_buffer_len)),
                          SymmetricKey::getInstance(secret));
}

SymmetricKeyPtr DHKEM::decapsulate(const PrivateKey & decapsulation_key, const ByteRange & wrapped_key, const ParameterList & parameters) const
{
    // Validate input key
    const auto& priv_key = checkDHKEMPrivateKey(decapsulation_key, _spec);
    
    // Customization
    auto info = _custom_info.byteRange();
    auto secret_size = _secret_size;

    // Validate parameters
    auto param_ctx = parameters.beginParameterProcessing();
    parameters.getBytes(KEY_ENCAPSULATION_PARAM_INFO, param_ctx, info);
    parameters.getSize(KEY_ENCAPSULATION_PARAM_SECRET_SIZE, param_ctx, secret_size);
    parameters.endParameterProcessing(param_ctx);

    // Decapsulate
    auto ctx = createHpkeContext(false);
    if (OSSL_HPKE_decap(ctx,
                        wrapped_key.data(), wrapped_key.size(),
                        priv_key.getEvpKey(),
                        nullptr, 0) != 1) {
        throw CryptoException("Failed to decapsulate secret key");
    }
    
    // Export
    auto secret = ByteArray(secret_size, 0);
    if (OSSL_HPKE_export(ctx, secret.data(), secret.size(), info.data(), info.size()) != 1) {
        throw CryptoException("Failed to export secret key");
    }

    // Return secret key
    return SymmetricKey::getInstance(secret);
}

const std::string & DHKEM::getAlgorithmName() const
{
    return _spec->name;
}

void DHKEM::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case KEY_ENCAPSULATION_PARAM_INFO:
            _custom_info = value.asByteRange();
            break;
        case KEY_ENCAPSULATION_PARAM_SECRET_SIZE:
            _secret_size = value.asSize();
            break;
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter DHKEM::getParameter(int param_id) const
{
    switch (param_id) {
        case KEY_ENCAPSULATION_PARAM_INFO:
            return Parameter::ref(_custom_info);
            
        case KEY_ENCAPSULATION_PARAM_SECRET_SIZE:
            return Parameter::take(_secret_size);
            
        default:
            throwUnsupportedParam(param_id);
    }
}

HPKEContext DHKEM::createHpkeContext(bool sender) const
{
    auto context = HPKEContext::take(OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, _spec->suite,
                                                       sender ? OSSL_HPKE_ROLE_SENDER : OSSL_HPKE_ROLE_RECEIVER,
                                                       ossl_ctx(), nullptr));
    if (!context.isValid()) {
        throw CryptoException("Failed to create HPKE context for DHKEM");
    }
    return context;
}


// MARK: - Utils

static bool isDHKEMKey(const Key& key) noexcept
{
    const auto & name = key.getKeyType();
    return  name == spec_P256_HKDF_SHA256.name ||
            name == spec_P384_HKDF_SHA384.name ||
            name == spec_P521_HKDF_SHA512.name;
}

const DHKEMPublicKey & checkDHKEMPublicKey(const PublicKey & public_key, const DHKEMSpec * expected_spec)
{
    auto key = isDHKEMKey(public_key) ? static_cast<const DHKEMPublicKey*>(&public_key) : nullptr;
    if (!key) {
        throw std::invalid_argument("Wrong public key type provided");
    }
    if (key->getRawKey().empty()) {
        throw std::invalid_argument("Empty public key type provided");
    }
    if (expected_spec && key->getKeyType() != expected_spec->name) {
        throw std::invalid_argument("Public key with different DHKEM setup provided");
    }
    return *key;
}

const DHKEMPrivateKey & checkDHKEMPrivateKey(const PrivateKey & private_key, const DHKEMSpec * expected_spec)
{
    auto key = isDHKEMKey(private_key) ? static_cast<const DHKEMPrivateKey*>(&private_key) : nullptr;
    if (!key) {
        throw std::invalid_argument("Wrong private key type provided");
    }
    if (!key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty private key type provided");
    }
    if (expected_spec && key->getKeyType() != expected_spec->name) {
        throw std::invalid_argument("Private key with different DHKEM setup provided");
    }
    return *key;
}

} // cc7::crypto
} // cc7
