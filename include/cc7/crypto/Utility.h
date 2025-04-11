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

#include <cc7/ByteArray.h>

namespace cc7
{
namespace crypto
{

/**
 Generates required amount of random bytes. if |reject_sequence_of_zeros|
 is true, then method will check whether the generated sequence contains
 only zeros and regenerate the data again.
 */
ByteArray GetRandomData(size_t size, bool reject_sequence_of_zeros = false);

/**
 Generates required amount of random bytes. It is guaranteed that the generated
 sequence is not equal to any byte sequence, provided in the |reject_byte_sequences|
 vector.
 */
ByteArray GetUniqueRandomData(size_t size, const std::vector<cc7::ByteRange> & reject_byte_sequences);

/**
 The function res-seeds OpenSSL's pseudo random number generator with another
 source of entropy. Typically, the "/dev/urandom" device is used.
 
 Note that if the library is using BoringSSL or LibreSSL as a crypto
 backend, then the re-seeding has no effect. These libraries doesn't
 implement RAND_seed() and other related functions.
 */
void ReseedRandomGenerator();

} // cc7::crypto
} // cc74
