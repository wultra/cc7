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

std::string KEY_FORMAT_RAW("cc7-format-raw");
std::string KEY_FORMAT_DER("cc7-format-der");
std::string KEY_FORMAT_DEFAULT = KEY_FORMAT_RAW;


std::string EC_PUBLIC_KEY_CONVERSION_COMPRESSED(OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED);
std::string EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED(OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED);

} // cc7::crypto
} // cc7

