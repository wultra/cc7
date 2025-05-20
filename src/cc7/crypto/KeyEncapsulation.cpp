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

#include <cc7/crypto/KeyEncapsulation.h>
#include <cc7/crypto/KeyDerivation.h>
#include "alg/MLKEM.h"

namespace cc7
{
namespace crypto
{

std::shared_ptr<KeyEncapsulation> KeyEncapsulation::getInstance(const std::string & algorithm, KeyDerivationPtr kdf)
{
    KeyEncapsulationPtr key_encap;
    if (stringHasPrefix(algorithm, "ML-KEM-")) {
        key_encap = MLKEM::getInstance(algorithm, kdf);
    }
    if (key_encap == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return key_encap;
}

std::shared_ptr<KeyEncapsulation> KeyEncapsulation::getInstance(const std::string & algorithm, const std::string & kdf_algorithm)
{
    return getInstance(algorithm, KeyDerivation::getInstance(kdf_algorithm));
}

} // cc7::crypto
} // cc7
