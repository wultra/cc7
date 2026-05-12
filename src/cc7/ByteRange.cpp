/*
 * Copyright 2016 Juraj Durech <durech.juraj@gmail.com>
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

#include <cc7/ByteRange.h>
#include <cc7/Base64.h>
#include <cc7/HexString.h>
#include <openssl/crypto.h>

namespace cc7 {

std::string ByteRange::base64(size_t wrap_size) const
{
    return Base64::encode(*this, wrap_size);
}

std::string ByteRange::base64() const noexcept
{
    return Base64::encode(*this, 0);
}

std::string ByteRange::base64Url() const noexcept
{
    return Base64::urlEncode(*this);
}

std::string ByteRange::hexadecimal(bool lower_case) const noexcept
{
    std::string result;
    HexString_Encode(*this, lower_case, result);
    return result;
}

// Legacy

std::string ByteRange::base64String(size_t wrap_size) const noexcept
{
    std::string result;
    Base64_Encode(*this, wrap_size, result);
    return result;
}

std::string ByteRange::hexString(bool lower_case) const noexcept
{
    std::string result;
    HexString_Encode(*this, lower_case, result);
    return result;
}

bool ConstTimeEqual(const ByteRange & a, const ByteRange & b)
{
    if (a.size() != b.size()) return false;
    if (a.size() == 0) return true;
    return CRYPTO_memcmp(a.begin(), b.begin(), a.size()) == 0;
}

} // cc7
