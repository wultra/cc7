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

namespace cc7
{
namespace crypto
{

// MARK: - ECCurveSpec structure

const ECCurveSpec ECCurveSpec::P_256 = { "P-256" };
const ECCurveSpec ECCurveSpec::P_384 = { "P-384" };
const ECCurveSpec ECCurveSpec::P_521 = { "P-521" };

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
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
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
    pub_key->importKey(ECPublicKey::exportKeyImpl(key_pair, EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED));
    priv_key->importKey(ECPrivateKey::exportKeyImpl(key_pair));
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

void ECPublicKey::importKey(const ByteRange & keyData, const std::string & format)
{
    checkConversionFormat(format);
    
    auto builder = OSSLParamBuilder::empty();
    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, curveName(), 0);
    OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, keyData.data(), keyData.size());
    
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
    if (!ctx.isValid() || EVP_PKEY_fromdata_init(ctx) <= 0) {
        throw std::domain_error("Failed to get and initialize EC public key context");
    }
    EVP_PKEY * pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        throw std::domain_error("Failed to import EC public key");
    }
    auto result = EVPKeyPair::take(pkey);
    if (!validatePublicKey(result)) {
        throw std::domain_error("Invalid EC public key");
    }
    getEvpKey() = result;
}

ByteArray ECPublicKey::exportKey(const std::string & format) const
{
    const std::string & key_format = checkConversionFormat(format);
    if (!_ll_key.isValid()) {
        throwInvalidKey(curveSpec()->name);
    }
    return exportKeyImpl(_ll_key, key_format);
}

ByteArray ECPublicKey::exportKeyImpl(const EVPKeyPair & ll_key, const std::string & key_format)
{
    if (!EVP_PKEY_set_utf8_string_param(ll_key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, key_format.c_str())) {
        throw std::domain_error("Failed to set EC_POINT conversion format to " + key_format);
    }
    return getByteArrayKeyParameter(ll_key, OSSL_PKEY_PARAM_PUB_KEY);
}

Parameter ECPublicKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

std::shared_ptr<Key> ECPublicKey::duplicate() const
{
    if (!_ll_key.isValid()) {
        throwInvalidKey(curveName());
    }
    auto duplicated = std::make_shared<ECPublicKey>(curveSpec());
    duplicated->importKey(exportKey(KEY_FORMAT_DEFAULT), KEY_FORMAT_DEFAULT);
    return duplicated;
}

bool ECPublicKey::validatePublicKey(EVPKeyPair & key)
{
    BIGNUM * coord_x = nullptr;
    BIGNUM * coord_y = nullptr;
    // Extract X
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &coord_x)) {
        return false;
    }
    auto x = BigNum::take(coord_x);
    // Extract Y
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &coord_y)) {
        return false;
    }
    auto y = BigNum::take(coord_y);
    // Check infinity
    if (BN_is_zero(x) || BN_is_zero(y)) {
        return false;
    }
    return true;
}

const std::string & ECPublicKey::checkConversionFormat(const std::string & format) const
{
    if (format == KEY_FORMAT_DEFAULT) {
        return EC_PUBLIC_KEY_CONVERSION_COMPRESSED;
    }
    if (format != EC_PUBLIC_KEY_CONVERSION_COMPRESSED && format != EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED) {
        throwUnsupportedKeyConversion(getKeyType(), format);
    }
    return format;
}


// MARK: - ECPrivateKey implementation

const std::string & ECPrivateKey::getKeyType() const
{
    return curveSpec()->name;
}

void ECPrivateKey::importKey(const ByteRange & keyData, const std::string & format)
{
    auto builder = OSSLParamBuilder::empty();
    auto privateKeyBN = BigNum_FromArray(keyData);
    OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, curveName(), 0);
    OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, privateKeyBN);
    
    auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
    auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
    if (!ctx.isValid() || EVP_PKEY_fromdata_init(ctx) <= 0) {
        throw std::domain_error("Failed to get and initialize EC public key context");
    }
    EVP_PKEY * pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) <= 0) {
        throw std::domain_error("Failed to import EC private key");
    }
    getEvpKey() = EVPKeyPair::take(pkey);
}

ByteArray ECPrivateKey::exportKey(const std::string & format) const
{
    if (format != KEY_FORMAT_DEFAULT) {
        throwUnsupportedKeyConversion(getKeyType(), format);
    }
    if (!_ll_key.isValid()) {
        throwInvalidKey(curveSpec()->name);
    }
    return exportKeyImpl(_ll_key);
}

ByteArray ECPrivateKey::exportKeyImpl(const EVPKeyPair &ll_key)
{
    BIGNUM * private_key = nullptr;
    if (!EVP_PKEY_get_bn_param(ll_key, OSSL_PKEY_PARAM_PRIV_KEY, &private_key)) {
        throw std::domain_error("Failed to export EC private key");
    }
    return BigNum_ToArray(BigNum::take(private_key));
}

Parameter ECPrivateKey::getKeyParameter(int param_id) const
{
    throwUnsupportedParam(param_id);
}

std::shared_ptr<Key> ECPrivateKey::duplicate() const
{
    if (!_ll_key.isValid()) {
        throwInvalidKey(curveName());
    }
    auto duplicated = std::make_shared<ECPublicKey>(curveSpec());
    duplicated->importKey(exportKey(KEY_FORMAT_DEFAULT), KEY_FORMAT_DEFAULT);
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
