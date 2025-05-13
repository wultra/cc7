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

// Key import / export formats

/// Specifies compressed format for elliptic curve based public keys.
extern std::string EC_PUBLIC_KEY_CONVERSION_COMPRESSED;
/// Specifies uncompressed format for elliptic curve based public keys.
extern std::string EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED;

enum KeyFormat
{
    /// The default format (depends on key type)
    KEY_FORMAT_DEFAULT,
    /// PKCS#8 format for private keys (DER encoded)
    KEY_FORMAT_PKCS8,
    /// SPKI (X509) for public keys (DER encoded)
    KEY_FORMAT_SPKI,
    /// SEC1 format (for EC private keys)
    KEY_FORMAT_SEC1,
    /// X9.62 / X9.63 (for EC public keys)
    KEY_FORMAT_X963,
    /// Format where typically a raw key information is encoded, with no additional information about
    /// key type.
    KEY_FORMAT_RAW
};

extern KeyFormat   KeyFormat_FromString(const std::string & str);
extern std::string KeyFormat_ToString(KeyFormat format, bool human_readable = false);

// Algorithm parameters

enum AlgorithmParameterId
{
    // Common
        
    // Key specific parameters
    
    /// Get EC public key X component. Parameter is byte range type.
    KEY_PARAM_EC_PUB_X          = 0x0020,
    
    /// Get EC public key Y component. Parameter is byte range type.
    KEY_PARAM_EC_PUB_Y,
    
    /// Set or get EC public point conversion. Parameter is string, use `EC_PUBLIC_KEY_CONVERSION_COMPRESSED`
    /// or `EC_PUBLIC_KEY_CONVERSION_UNCOMPRESSED` (default).
    KEY_PARAM_EC_POINT_CONVERSION,
    
    // MAC
    
    /// Alter length of output digest. Parameter is size type.
    MAC_PARAM_DIGEST_LENGTH     = 0x0040,
    
    /// Alter custom context string in MAC algorithm. Parameter is string type.
    ///
    /// Be aware that underlying implementation may use a shared buffer for this parameter and `MAC_PARAM_CUSTOM_DATA`,
    /// so don't mix such parameters in one instance of MAC algorithm.
    MAC_PARAM_CUSTOM_STRING,
    
    /// Alter custom context data in MAC algorithm. Parameter is byte range type.
    ///
    /// Be aware that underlying implementation may use a shared buffer for this parameter and `MAC_PARAM_CUSTOM_STRING`,
    /// so don't mix such parameters in one instance of MAC algorithm.
    MAC_PARAM_CUSTOM_DATA,
    
    // KDF

    /// Alter output key type returned from KDF algorithm. Parameter is string type.
    KDF_PARAM_KEY_TYPE          = 0x0060,
    /// Alter output key size returned from KDF algorithm. Parameter is size type.
    KDF_PARAM_KEY_SIZE,
    /// Provide salt to KDF algorithm. Parameter is byte range type.
    KDF_PARAM_SALT,
    /// Provide number of iterations to KDF algorithm. Parameter is size type.
    KDF_PARAM_ITERATIONS,
    /// Provide additional info bytes to KDF algorithm. Parameter is byte range type.
    KDF_PARAM_INFO,
    
    // Cipher

    /// Get length of IV. Parameter is size type and is read only.
    CIPHER_PARAM_IV_LENGTH      = 0x0080,
    /// Get length of TAG. Parameter is size type and is read only.
    /// Note that if zero is returned, then TAG and AAD is not supported.
    CIPHER_PARAM_TAG_LENGTH,
    /// Set or get authentication tag. The parameter type depends on encryption or decryption:
    /// - For ecnryption, parameter is output array type. You should provide array where the calculated tag will be stored.
    /// - For decryption, use byte range type with calculated tag.
    CIPHER_PARAM_TAG,
    /// Set AAD (additional authenticated data) if cipher supports it. Parameter is byte range type.
    CIPHER_PARAM_AAD,
    
    /// Enable or disable padding. Parameter is bool type.
    CIPHER_PARAM_USE_PADDING,
    
    /// AEAD
    /// Provide additional key context bytes to AEAD algorithm. Parameter is byte range type.
    AEAD_PARAM_KEY_CONTEXT      = 0x00A0,
    
    // KeyAgreement
    
    /// Alter KDF function in KeyAgreement algorithm. Parameter is KeyDerivation object.
    KEY_AGREEMENT_PARAM_KDF     = 0x00C0,
};

} // cc7::crypto
} // cc7

