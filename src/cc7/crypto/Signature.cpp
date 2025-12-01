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

#include <cc7/crypto/Signature.h>
#include "alg/MLDSA.h"
#include "alg/ECDSA.h"

namespace cc7::crypto {

std::shared_ptr<Signature> Signature::getInstance(const std::string & algorithm)
{
    std::shared_ptr<Signature> signature;
    if (stringHasPrefix(algorithm, "ECDSA-")) {
        signature = ECDSA::getInstance(algorithm);
    } else if (stringHasPrefix(algorithm, "ML-DSA-")) {
        signature = MLDSA::getInstance(algorithm);
    }
    if (signature == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return signature;
}

} // namespace cc7::crypto
