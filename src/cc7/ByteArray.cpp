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

#include <cc7/ByteArray.h>
#include <cc7/Base64.h>
#include <cc7/HexString.h>

namespace cc7 {

// New methods

void ByteArray::readFromBase64(const std::string & base64_string, size_t wrap_size)
{
    *this = Base64::decode(base64_string, wrap_size);
}

void ByteArray::readFromBase64Url(const std::string & base64url_string)
{
    *this = Base64::urlDecode(base64url_string);
}

void ByteArray::readFromHexadecimal(const std::string & hex_string)
{
    if (!HexString_Decode(hex_string, *this)) {
        throw std::domain_error("Input is not hexadecimal string");
    }
}

std::string ByteArray::base64(size_t wrap_size) const
{
    return Base64::encode(*this, wrap_size);
}

std::string ByteArray::base64() const noexcept
{
    return Base64::encode(*this, 0);
}

std::string ByteArray::base64Url() const noexcept
{
    return Base64::urlEncode(*this);
}

std::string ByteArray::hexadecimal(bool lower_case) const noexcept
{
    std::string result;
    HexString_Encode(*this, lower_case, result);
    return result;
}


// Legacy

bool ByteArray::readFromBase64String(const std::string & base64_string, size_t wrap_size) noexcept
{
    return Base64_Decode(base64_string, wrap_size, *this);
}

bool ByteArray::readFromHexString(const std::string & hex_string) noexcept
{
    return HexString_Decode(hex_string, *this);
}

std::string ByteArray::base64String(size_t wrap_size) const noexcept
{
    std::string result;
    Base64_Encode(*this, wrap_size, result);
    return result;
}

std::string ByteArray::hexString(bool lower_case) const noexcept
{
    std::string result;
    HexString_Encode(this->byteRange(), lower_case, result);
    return result;
}

// Concat

cc7::ByteArray ConcatByteRanges(std::initializer_list<cc7::ByteRange> components)
{
    auto it = components.begin();
    size_t reserved_bytes = 0;
    while (it != components.end()) {
        reserved_bytes += it->size();
        ++it;
    }
    cc7::ByteArray result;
    result.reserve(reserved_bytes);
    it = components.begin();
    while (it != components.end()) {
        result.append(*it);
        ++it;
    }
    return result;
}

cc7::ByteArray ConcatByteRanges(const std::vector<ByteRange>& components)
{
    auto it = components.begin();
    size_t reserved_bytes = 0;
    while (it != components.end()) {
        reserved_bytes += it->size();
        ++it;
    }
    cc7::ByteArray result;
    result.reserve(reserved_bytes);
    it = components.begin();
    while (it != components.end()) {
        result.append(*it);
        ++it;
    }
    return result;
}

} // cc7
