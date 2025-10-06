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

#include <cc7/BaseObject.h>
#include <cc7/crypto/KeyPair.h>
#include <cc7/crypto/SymmetricKey.h>
#include <cc7/jwt/JwtException.h>

namespace cc7 {
namespace jwt {

class JwsKey : public BaseObject
{
public:
    
    enum class Type
    {
        SYMMETRIC,
        PUBLIC,
        PRIVATE
    };
    
    Type getType() const;
    const std::string& getJwtAlgorithm() const;
    
    const crypto::PublicKey& getPublicKey() const;
    const crypto::PrivateKey& getPrivateKey() const;
    const crypto::SymmetricKey& getSymmetricKey() const;
    
    static std::shared_ptr<JwsKey> symmetricKey(const std::string & algorithm, const crypto::ConstSymmetricKeyPtr& symmetric_key);
    static std::shared_ptr<JwsKey> symmetricKey(const std::string & algorithm, const ByteRange& key_data);
    static std::shared_ptr<JwsKey> publicKey(const std::string& algorithm, const crypto::ConstPublicKeyPtr& public_key);
    static std::shared_ptr<JwsKey> publicKey(const crypto::ConstPublicKeyPtr& public_key);
    static std::shared_ptr<JwsKey> privateKey(const std::string& algorithm, const crypto::ConstPrivateKeyPtr& private_key);
    static std::shared_ptr<JwsKey> privateKey(const crypto::ConstPrivateKeyPtr& private_key);
private:
    
    JwsKey(Type type, const std::string& algorithm, const crypto::ConstKeyPtr& key);
    

    const Type _type;
    const std::string _algorithm;
    const crypto::ConstKeyPtr _key;
    
    void checkKeyType(Type t) const;
    static const std::string& getAlgorithmForKey(const crypto::Key& key);
};

CC7_SHARED_PTR(JwsKey)
typedef std::vector<JwsKeyPtr> JwsKeyList;


} // namespace jwt
} // namespace cc7
