/*
 * Copyright 2016 Juraj Durech <durech.juraj@gmail.com>
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

/// The `Base64` class provides routines for Base64 and Base64Url encoding and decoding.
class Base64 {
    Base64() = delete;
public:
    enum Wrap
    {
        /// Do not split string into lines, or don't except string divided into multiple lines.
        NONE = 0,
        /// Use 64 characters per line (RFC 1421 - PEM)
        WRAP_64 = 64,
        /// Use 76 characters per line (RFC 2045 - MIME, RFC 9580)
        WRAP_76 = 76
    };

    
    /// Encode data into standard Base64 encoding.
    /// - Parameters:
    ///   - data: Range of bytes to encode.
    ///   - wrap_size: If not 0, then output is split into the multiple lines with required maximum number of characters per line.
    /// - Returns: Input range represented as Base64 encoded string.
    /// - Throws:
    ///   - `std::invalid_argument` if `wrap_size` is not divisible by 4.
    static std::string encode(const ByteRange& data, size_t wrap_size = NONE);
    
    /// Encode data into standard Base64 encoding. The string is securely stored into ByteArray.
    /// - Parameters:
    ///   - data: Range of bytes to encode.
    ///   - wrap_size: If not 0, then output is split into the multiple lines with required maximum number of characters per line.
    /// - Returns: Input range represented as Base64 encoded string.
    /// - Throws:
    ///   - `std::invalid_argument` if `wrap_size` is not divisible by 4.
    static ByteArray secureEncode(const ByteRange& data, size_t wrap_size = NONE);
    
    /// Decode Base64 encoded string into array of bytes.
    /// - Parameters:
    ///   - data: Base64 encoded string.
    ///   - wrap_size: If not 0, then multiline string with required number of characters per line is expected at input.
    /// - Throws:
    ///   - `std::invalid_argument` if `wrap_size` is not divisible by 4.
    ///   - `std::domain_error` if input is not Base64 string.
    static ByteArray decode(const std::string_view& data, size_t wrap_size = NONE);
    
    /// Encode data into Base64Url encoding.
    /// - Parameters:
    ///   - data: Range of bytes to encode.
    /// - Returns: Input range represented as Base64Url encoded string.
    static std::string urlEncode(const ByteRange& data) noexcept;
    
    /// Encode data into Base64Url encoding. The string is securely stored into ByteArray.
    /// - Parameters:
    ///   - data: Range of bytes to encode.
    /// - Returns: Input range represented as Base64Url encoded string.
    static ByteArray secureUrlEncode(const ByteRange& data) noexcept;
    
    /// Decode Base64Url encoded string into array of bytes.
    /// - Parameters:
    ///   - data: Base64Url encoded string.
    ///   - wrap_size: If not 0, then multiline string with required number of characters per line is expected at input.
    /// - Throws:
    ///   - `std::invalid_argument` if `wrap_size` is not divisible by 4.
    ///   - `std::domain_error` if input is not Base64Url string.
    static ByteArray urlDecode(const std::string_view& data);
};

// Legacy functions

/**
 Converts input byte range into Base64 encoded string. The function returns false
 only if you provide an invalid |wrap_size| parameter.
 */
bool Base64_Encode(const ByteRange & in_data, size_t wrap_size, std::string & out_string) noexcept;

/**
 Converts Base64 encoded string into ByteArray. If the |wrap_size| parameter is greater than 0
 then the multiline input string is expected. In this case, the size of wrapping is just a hint
 and the decoder can process strings with a different size of lines.
 
 Returns false if the string is not a valid Base64 string.
 
 Note that unlike the other Base64 implementations, this decoder treats invalid characters in the string
 as an error. Other implementations usually stops processing at first invalid character.
 */
bool Base64_Decode(const std::string_view & in_string, size_t wrap_size, ByteArray & out_data) noexcept;

/**
 Converts input byte range into Base64 encoded string. This variant of encoding function may be
 easier to use, but unlike the Base64_Encode(), you are not able to determine whether
 the error occured or not.
 */
std::string ToBase64String(const ByteRange & data, size_t wrap_size = 0) noexcept;

/**
 Converts Base64 encoded string into ByteArray. This variant of decoding function may be
 easier to use, but unlike the Base64_Decode(), you are not able to determine whether
 the error occured or not.
 */
ByteArray FromBase64String(const std::string_view & string, size_t wrap_size = 0) noexcept;
    
} // cc7
