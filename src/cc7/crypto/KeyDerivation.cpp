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

#include <cc7/crypto/KeyDerivation.h>
#include "alg/NullKDF.h"
#include "alg/X963KDF.h"
#include "alg/PBKDF2.h"

namespace cc7::crypto {

std::shared_ptr<KeyDerivation> KeyDerivation::getInstance(const std::string & algorithm)
{
    KeyDerivationPtr kdf;
    if (algorithm == NullKDF::NULL_KDF) {
        kdf = noDerivation();
    }
    if (kdf == nullptr) {
        kdf = X963KDF::getInstance(algorithm);
    }
    if (kdf == nullptr) {
        kdf = PBKDF2::getInstance(algorithm);
    }
    if (kdf == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return kdf;
}

std::shared_ptr<KeyDerivation> KeyDerivation::noDerivation()
{
    return std::shared_ptr<KeyDerivation>(new NullKDF());
}

SymmetricKeyPtr KeyDerivation::deriveKey(const ByteRange & key_material,
                                         const ParameterList & parameters) const
{
    return SymmetricKey::getInstance(deriveKeyBytes(key_material, parameters));
}

SymmetricKeyPtr KeyDerivation::deriveKey(const SymmetricKey & key,
                                         const std::string & out_key_type,
                                         const ParameterList & parameters) const
{
    ByteArray derived_key_material;
    if (key.getKeyContext().empty()) {
        derived_key_material = deriveKeyBytes(key.getKeyData(), parameters);
    } else {
        auto p = parameters;
        p[PARAM_KEY_CONTEXT] = Parameter::ref(key.getKeyContext());
        derived_key_material = deriveKeyBytes(key.getKeyData(), p);
    }
    return SymmetricKey::getInstance(out_key_type, derived_key_material);
}

} // namespace cc7::crypto
