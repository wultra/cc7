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

#include "detail/OSSLObjects.h"
#include <cc7/crypto/CryptoConstants.h>
#include <cc7/crypto/CryptoException.h>
#include <cc7/crypto/KeyPair.h>

namespace cc7::crypto {

void throwUnsupporterAlgorithm [[noreturn]] (const std::string & alg_name);

void throwUnsupportedParam [[noreturn]] (int param_id);

void throwUnsupportedKeyFormat [[noreturn]] (const std::string & key_type, KeyFormat format);

void throwInvalidKey [[noreturn]] (const std::string & key_type);

void throwSealedKey [[noreturn]] (const std::string & key_type);

bool stringHasPrefix(const std::string & str, const std::string & prefix);
bool stringHasSuffix(const std::string & str, const std::string & suffix);
std::string stringJoin(const std::vector<std::string>& items, const std::string& separator);

OSSL_LIB_CTX * ossl_ctx();

/// Extract low-level key from given public key object. If such key is not supported,
/// then throws `std::invalid_argument` exception.
/// - Parameter public_key: Public key object.
EVPKeyPair getLLKey(const PublicKey& public_key);

/// Extract low-level key from given private key object. If such key is not supported,
/// then throws `std::invalid_argument` exception.
/// - Parameters:
///   - private_key: Private key object.
///   - check_signing: If true, then also check capability to sign data with the key.
EVPKeyPair getLLKey(const PrivateKey& private_key, bool check_signing);

} // namespace cc7::crypto
