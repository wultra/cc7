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

namespace cc7
{
namespace crypto
{

void throwUnsupporterAlgorithm [[noreturn]] (const std::string & alg_name);

void throwUnsupportedParam [[noreturn]] (int param_id);

void throwUnsupportedKeyConversion [[noreturn]] (const std::string & key_type, const std::string & conv_format);

void throwInvalidKey [[noreturn]] (const std::string & key_type);

bool stringHasPrefix(const std::string & str, const std::string & prefix);

cc7::ByteArray getByteArrayKeyParameter(const EVPKeyPair & key, const char * param_name);

} // cc7::crypto
} // cc7

