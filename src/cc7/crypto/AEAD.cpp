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

#include <cc7/crypto/AEAD.h>
#include "alg/AES.h"

namespace cc7::crypto {

AEADPtr AEAD::getInstance(const std::string &algorithm)
{
    AEADPtr aead;
    if (stringHasPrefix(algorithm, "AES-")) {
        aead = AES_GCM_AEAD::getInstance(algorithm);
    }
    if (aead == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return aead;
}

ByteArray AEAD::seal(const SymmetricKey & key,
                     const ByteRange & nonce,
                     const ByteRange & associated_data,
                     const ByteRange & plaintext,
                     const ParameterList & params) const
{
    if (key.getKeyContext().empty()) {
        return seal(key.getKeyData().byteRange(), nonce, associated_data, plaintext, params);
    }
    auto p = params;
    p[PARAM_KEY_CONTEXT] = Parameter::ref(key.getKeyContext());
    return seal(key.getKeyData().byteRange(), nonce, associated_data, plaintext, p);
}

ByteArray AEAD::open(const SymmetricKey & key,
                     const ByteRange & associated_data,
                     const ByteRange & ciphertext,
                     const ParameterList & params) const
{
    if (key.getKeyContext().empty()) {
        return open(key.getKeyData().byteRange(), associated_data, ciphertext, params);
    }
    auto p = params;
    p[PARAM_KEY_CONTEXT] = Parameter::ref(key.getKeyContext());
    return open(key.getKeyData().byteRange(), associated_data, ciphertext, p);
}

} // namespace cc7::crypto
