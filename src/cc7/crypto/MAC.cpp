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

#include <cc7/crypto/MAC.h>
#include "alg/KMAC.h"
#include "alg/HMAC.h"

namespace cc7::crypto {

std::shared_ptr<MAC> MAC::getInstance(const std::string & algorithm)
{
    std::shared_ptr<MAC> mac;
    if (stringHasPrefix(algorithm, "KMAC")) {
        mac = KMAC::getInstance(algorithm);
    } else if (stringHasPrefix(algorithm, "HMAC-")) {
        mac = HMAC::getInstance(algorithm);
    }
    if (mac == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return mac;
}

} // namespace cc7::crypto
