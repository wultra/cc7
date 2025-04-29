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

#include "ECKeyPair.h"
#include "KeyUtility.h"

namespace cc7
{
namespace crypto
{

// MARK: - ECCurveSpec structure

const ECCurveSpec ECCurveSpec::P_256 = { "P-256", "prime256v1" };
const ECCurveSpec ECCurveSpec::P_384 = { "P-384", "secp384r1" };
const ECCurveSpec ECCurveSpec::P_521 = { "P-521", "secp521r1" };

const ECCurveSpec * ECCurveSpec::nameToCurveSpec(const std::string & name)
{
    if (name == P_256.name) {
        return &P_256;
    } else if (name == P_384.name) {
        return &P_384;
    } else if (name == P_521.name) {
        return  &P_521;
    }
    return nullptr;
}

// MARK: - ECKeyPairFactory implementation

KeyPairFactoryPtr ECKeyPairFactory::getInstance(const std::string & algorithm)
{
    auto spec = ECCurveSpec::nameToCurveSpec(algorithm);
    if (!spec) {
        return nullptr;
    }
    return KeyPairFactoryPtr(new ECKeyPairFactory(spec));

}

// KeyPairFactory interface

KeyPairPtr ECKeyPairFactory::generateKeyPair() const
{
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(ossl_ctx(), "EC", NULL));
    if (!ctx.isValid()) {
        throw std::domain_error("Failed to fetch EC key context");
    }
    // Initialize keygen
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        throw std::domain_error("Failed to initialize EC key generator");
    }
    // Set the curve
    if (EVP_PKEY_CTX_set_group_name(ctx, algName()) <= 0) {
        throw std::domain_error("Failed to set EC group name");
    }
    EVP_PKEY * pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        throw std::domain_error("Failed to generate new EC key pair");
    }
    auto key_pair = EVPKeyPair::take(pkey);
    auto pub_key = newPublicKey();
    auto priv_key = newPrivateKey();
    pub_key->importKey(exportPublicKey(key_pair, _curve->name, KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    priv_key->importKey(exportPrivateKey(key_pair, _curve->name, KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    return std::make_shared<KeyPair>(pub_key, priv_key);
}

PublicKeyPtr ECKeyPairFactory::newPublicKey() const
{
    return PublicKeyPtr(new ECPublicKey(algSpec()));
}

PrivateKeyPtr ECKeyPairFactory::newPrivateKey() const
{
    return PrivateKeyPtr(new ECPrivateKey(algSpec()));
}

// Algorithm interface

const std::string & ECKeyPairFactory::getAlgorithmName() const
{
    return algSpec()->name;
}

void ECKeyPairFactory::setParameter(int param_id, const Parameter & value)
{
    throwUnsupportedParam(param_id);
}

Parameter ECKeyPairFactory::getParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}


// MARK: - ECPublicKey implementation

const std::string & ECPublicKey::getKeyType() const
{
    return curveSpec()->name;
}

void ECPublicKey::importKey(const ByteRange & keyData, KeyFormat format)
{
    getEvpKey() = importPublicKey(curveSpec()->name, format, keyData);
}

ByteArray ECPublicKey::exportKey(KeyFormat format) const
{
    return exportPublicKey(_ll_key, curveSpec()->name, format);
}

Parameter ECPublicKey::getKeyParameter(int param_id) const
{
    switch (param_id) {
        case KEY_PARAM_EC_PUB_X:
            EVPKeyPair_CheckValid(_ll_key, curveSpec()->name);
            return Parameter::copyFrom(EVPKeyPair_GetBigNumParam(_ll_key, OSSL_PKEY_PARAM_EC_PUB_X));
        case KEY_PARAM_EC_PUB_Y:
            EVPKeyPair_CheckValid(_ll_key, curveSpec()->name);
            return Parameter::copyFrom(EVPKeyPair_GetBigNumParam(_ll_key, OSSL_PKEY_PARAM_EC_PUB_Y));
        case KEY_PARAM_EC_POINT_CONVERSION:
            EVPKeyPair_CheckValid(_ll_key, curveSpec()->name);
            return Parameter::copyFrom(EVPKeyPair_GetStringParam(_ll_key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT));
        default:
            throwUnsupportedParam(param_id);
    }
}

void ECPublicKey::setKeyParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case KEY_PARAM_EC_POINT_CONVERSION:
            EVPKeyPair_CheckValid(_ll_key, curveSpec()->name);
            EVPKeyPair_SetStringParam(_ll_key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, value.asString());
            break;
            
        default:
            throwUnsupportedParam(param_id);
    }
}

std::shared_ptr<Key> ECPublicKey::duplicate() const
{
    auto duplicated = std::make_shared<ECPublicKey>(curveSpec());
    if (_ll_key.isValid()) {
        duplicated->importKey(exportKey(KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    }
    return duplicated;
}


// MARK: - ECPrivateKey implementation

const std::string & ECPrivateKey::getKeyType() const
{
    return curveSpec()->name;
}

void ECPrivateKey::importKey(const ByteRange & keyData, KeyFormat format)
{
    getEvpKey() = importPrivateKey(curveSpec()->name, format, keyData);
}

ByteArray ECPrivateKey::exportKey(KeyFormat format) const
{
    return exportPrivateKey(_ll_key, curveSpec()->name, format);
}

Parameter ECPrivateKey::getKeyParameter(int param_id) const
{
    switch (param_id) {
        case KEY_PARAM_EC_POINT_CONVERSION:
            // Private key encodes also public key in some formats, so it makes sense to support this parameter.
            EVPKeyPair_CheckValid(_ll_key, curveSpec()->name);
            return Parameter::copyFrom(EVPKeyPair_GetStringParam(_ll_key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT));

        default:
            throwUnsupportedParam(param_id);
    }
}

void ECPrivateKey::setKeyParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case KEY_PARAM_EC_POINT_CONVERSION:
            // Private key encodes also public key, so it makes sense to support this parameter.
            EVPKeyPair_CheckValid(_ll_key, curveSpec()->name);
            EVPKeyPair_SetStringParam(_ll_key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, value.asString());
            break;
            
        default:
            throwUnsupportedParam(param_id);
    }
}

std::shared_ptr<Key> ECPrivateKey::duplicate() const
{
    auto duplicated = std::make_shared<ECPrivateKey>(curveSpec());
    if (_ll_key.isValid()) {
        duplicated->importKey(exportKey(KEY_FORMAT_RAW), KEY_FORMAT_RAW);
    }
    return duplicated;
}


// MARK: - Support functions

const ECPublicKey & checkECPublicKey(const PublicKey & public_key, const ECCurveSpec * expected_curve)
{
    auto ec_key = dynamic_cast<const ECPublicKey*>(&public_key);
    if (!ec_key) {
        throw std::invalid_argument("Wrong public key type provided");
    }
    if (!ec_key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty public key type provided");
    }
    if (expected_curve && ec_key->curveSpec() != expected_curve) {
        throw std::invalid_argument("Public key with unsupported elliptic curve provided");
    }
    return *ec_key;
}

const ECPrivateKey & checkECPrivateKey(const PrivateKey & private_key, const ECCurveSpec * expected_curve, bool check_signing)
{
    auto ec_key = dynamic_cast<const ECPrivateKey*>(&private_key);
    if (!ec_key) {
        throw std::invalid_argument("Wrong private key type provided");
    }
    if (!ec_key->getEvpKey().isValid()) {
        throw std::invalid_argument("Empty private key type provided");
    }
    if (check_signing) {
        if (!EVP_PKEY_can_sign(ec_key->getEvpKey())) {
            throw std::invalid_argument("Provided private key cannot sign data");
        }
    }
    if (expected_curve && ec_key->curveSpec() != expected_curve) {
        throw std::invalid_argument("Private key with unsupported elliptic curve provided");
    }
    return *ec_key;
}

} // cc7::crypto
} // cc7
