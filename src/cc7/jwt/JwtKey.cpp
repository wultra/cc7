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

#include <cc7/jwt/JwtKey.h>
#include "JwsSpec.h"

namespace cc7 {
namespace jwt {

JwtKey::JwtKey(Type type, const std::string& algorithm, const crypto::KeyPtr& key) :
    _type(type),
    _algorithm(algorithm),
    _key(key)
{
}

JwtKey::Type JwtKey::getType() const
{
    return _type;
}

const std::string& JwtKey::getJwtAlgorithm() const
{
    return _algorithm;
}

const crypto::PublicKey& JwtKey::getPublicKey() const
{
    checkKeyType(Type::PUBLIC);
    return reinterpret_cast<crypto::PublicKey&>(*_key);
}

const crypto::PrivateKey& JwtKey::getPrivateKey() const
{
    checkKeyType(Type::PRIVATE);
    return reinterpret_cast<crypto::PrivateKey&>(*_key);
}

const crypto::SymmetricKey& JwtKey::getSymmetricKey() const
{
    checkKeyType(Type::SYMMETRIC);
    return reinterpret_cast<crypto::SymmetricKey&>(*_key);
}

JwtKeyPtr JwtKey::symmetricKey(const std::string & algorithm, const ByteRange& key_data)
{
    return symmetricKey(algorithm, crypto::SymmetricKey::getInstance(key_data));
}

JwtKeyPtr JwtKey::symmetricKey(const std::string & algorithm, const crypto::SymmetricKeyPtr& symmetric_key)
{
    // Check whether algorithm is supported.
    if (!JwsSpec::specForJwsAlgorithm(algorithm)) {
        throw JwtException("Unsupported JWT algorithm " + algorithm);
    }
    return std::shared_ptr<JwtKey>(new JwtKey(Type::SYMMETRIC, algorithm, symmetric_key));
}

JwtKeyPtr JwtKey::publicKey(const crypto::PublicKeyPtr& public_key)
{
    return std::shared_ptr<JwtKey>(new JwtKey(Type::PUBLIC,
                                              getAlgorithmForKey(*public_key),
                                              public_key));
}

JwtKeyPtr JwtKey::privateKey(const crypto::PrivateKeyPtr& private_key)
{
    return std::shared_ptr<JwtKey>(new JwtKey(Type::PRIVATE,
                                              getAlgorithmForKey(*private_key),
                                              private_key));
}

static std::string _TypeToName(JwtKey::Type t)
{
    switch (t) {
        case JwtKey::Type::SYMMETRIC: return "SYMMETRIC";
        case JwtKey::Type::PUBLIC: return "PUBLIC";
        case JwtKey::Type::PRIVATE: return "PRIVATE";
    }
}

void JwtKey::checkKeyType(Type t) const
{
    if (_type != t) {
        throw std::logic_error("Requesting " + _TypeToName(t) + " key, while key is " + _algorithm + "/" + _TypeToName(_type));
    }
}

const std::string& JwtKey::getAlgorithmForKey(const crypto::Key &key)
{
    const auto spec = JwsSpec::specForKeyAlgorithm(key.getKeyType());
    if (!spec) {
        throw JwtException("Unsupported key algorithm " + key.getKeyType());
    }
    return spec->jwsName;
}

} // namespace jwt
} // namespace cc7

