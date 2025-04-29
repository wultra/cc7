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

#include <cc7/crypto/Constants.h>
#include "CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

std::string EC_PUBLIC_KEY_CONVERSION_COMPRESSED(OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED);
std::string EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED(OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED);

KeyFormat KeyFormat_FromString(const std::string & str)
{
    if (str == "raw")     return KEY_FORMAT_RAW;
    if (str == "sec1")    return KEY_FORMAT_SEC1;
    if (str == "pkcs8")   return KEY_FORMAT_PKCS8;
    if (str == "spki")    return KEY_FORMAT_SPKI;
    if (str == "x963")    return KEY_FORMAT_X963;
    if (str == "default") return KEY_FORMAT_DEFAULT;
    throw std::invalid_argument("Unsupported key format");
}

std::string KeyFormat_ToString(KeyFormat format, bool human_readable)
{
    switch (format) {
        case KEY_FORMAT_RAW:     return "raw";
        case KEY_FORMAT_SEC1:    return human_readable ? "SEC.1" : "sec1";
        case KEY_FORMAT_PKCS8:   return human_readable ? "PKCS#8" : "pkcs8";
        case KEY_FORMAT_SPKI:    return "spki";
        case KEY_FORMAT_X963:    return human_readable ? "X9.63" : "x963";
        case KEY_FORMAT_DEFAULT: return "default";
        default:                 throw std::invalid_argument("Unknown key format");
    }
}

} // cc7::crypto
} // cc7

