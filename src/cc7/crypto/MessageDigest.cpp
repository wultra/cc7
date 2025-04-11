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

#include <cc7/crypto/MessageDigest.h>
#include "alg/SHA.h"

namespace cc7
{
namespace crypto
{

std::shared_ptr<MessageDigest> MessageDigest::getInstance(const std::string & algorithm)
{
    std::shared_ptr<MessageDigest> message_digest;
    if (stringHasPrefix(algorithm, "SHA-") || stringHasPrefix(algorithm, "SHA3-")) {
        message_digest = SHA::getInstance(algorithm);
    }
    if (message_digest == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return message_digest;
}

} // cc7::crypto
} // cc7
