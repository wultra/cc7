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

#include <cc7/Platform.h>

namespace cc7
{
namespace crypto
{

// Key import exrpot formats

/// The default format, equal to `KEY_FORMAT_RAW`
extern std::string KEY_FORMAT_DEFAULT;
/// Format where no additional information, such as information about key type, is added.
/// This is the default import-export key format.
extern std::string KEY_FORMAT_RAW;
/// DER format, including informatou about key type is included.
extern std::string KEY_FORMAT_DER;
/// Specifies compressed format for elliptic curve based public keys.
extern std::string EC_PUBLIC_KEY_CONVERSION_COMPRESSED;
/// Specifies uncompressed format for elliptic curve based public keys.
extern std::string EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED;

// Algorithm parameters

enum AlgorithmParameterId
{
    // Common
    
    /// Alter output key type. Parameter is string type.
    PARAM_OUT_KEY_TYPE          = 0x0001,
    
    // MAC
    
    /// Alter length of output digest. Parameter is size type.
    MAC_PARAM_DIGEST_LENGTH     = 0x0100,
    
    /// Alter custom context string in MAC algorithm. Parameter is string type.
    ///
    /// Be aware that underlying implementation may use a shared buffer for this parameter and `MAC_PARAM_CUSTOM_DATA`,
    /// so don't mix such parameters in one instance of MAC algorithm.
    MAC_PARAM_CUSTOM_STRING,
    
    /// Alter custom context data in MAC algorithm. Parameter is string type.
    ///
    /// Be aware that underlying implementation may use a shared buffer for this parameter and `MAC_PARAM_CUSTOM_STRING`,
    /// so don't mix such parameters in one instance of MAC algorithm.
    MAC_PARAM_CUSTOM_DATA,
    
    // KDF
    
    // Cipher
    CIPHER_PARAM_IV             = 0x0300,
    CIPHER_PARAM_IV_LENGTH,
    
    // KeyAgreement
    
    /// Alter KDF function in KeyAgreement algorithm. Parameter is KeyDerivation object.
    KEY_AGREEMENT_PARAM_KDF     = 0x0400,
};

} // cc7::crypto
} // cc7

