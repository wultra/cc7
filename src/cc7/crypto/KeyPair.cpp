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

#include <cc7/crypto/KeyPair.h>
#include "alg/MLDSA.h"
#include "alg/MLKEM.h"
#include "alg/DHKEM.h"
#include "alg/ECKeyPair.h"

namespace cc7 {
namespace crypto {

// MARK: - KeyPairFactory implementation

KeyPairFactoryPtr KeyPairFactory::getInstance(const std::string & key_type)
{
    std::shared_ptr<KeyPairFactory> factory;
    if (stringHasPrefix(key_type, "P-")) {
        factory = ECKeyPairFactory::getInstance(key_type);
    } else if (stringHasPrefix(key_type, "ML-DSA-")) {
        factory = MLDSAKeyPairFactory::getInstance(key_type);
    } else if (stringHasPrefix(key_type, "ML-KEM-")) {
        factory = MLKEMKeyPairFactory::getInstance(key_type);
    } else if (stringHasPrefix(key_type, "DHKEM-")) {
        factory = DHKEMKeyPairFactory::getInstance(key_type);
    }
    if (factory == nullptr) {
        throw UnsupportedAlgorithm("Unsupported key type " + key_type);
    }
    return factory;
}


// MARK: - PrivateKey implementation

std::shared_ptr<PrivateKey> PrivateKey::getInstance(const std::string & key_type)
{
    return KeyPairFactory::getInstance(key_type)->newPrivateKey();
}


// MARK: - PublicKey implementation

std::shared_ptr<PublicKey> PublicKey::getInstance(const std::string & key_type)
{
    return KeyPairFactory::getInstance(key_type)->newPublicKey();
}


// MARK: - KeyPair implementation

std::shared_ptr<KeyPair> KeyPair::generateKeyPair(const std::string & key_type)
{
    return KeyPairFactory::getInstance(key_type)->generateKeyPair();
}

} // cc7::crypto
} // cc7
