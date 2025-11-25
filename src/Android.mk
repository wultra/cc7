#
# Copyright 2016 Juraj Durech <durech.juraj@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH:= $(call my-dir)

# -------------------------------------------------------------------------
# Prebuilt OpenSSL crypto library
# -------------------------------------------------------------------------

include $(CLEAR_VARS)
LOCAL_MODULE          	:= openssl_crypto
LOCAL_SRC_FILES			:= ../openssl-lib/android/lib/$(TARGET_ARCH_ABI)/libcrypto.a
LOCAL_EXPORT_C_INCLUDES	:= ../openssl-lib/android/include
include $(PREBUILT_STATIC_LIBRARY)

# -------------------------------------------------------------------------
# CC7 library
# -------------------------------------------------------------------------

include $(CLEAR_VARS)

NDK_TOOLCHAIN_VERSION := clang

# Library name
LOCAL_MODULE			:= libcc7
LOCAL_CFLAGS			:= $(EXTERN_CFLAGS)
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -std=c++17 -frtti
LOCAL_CPP_FEATURES		+= exceptions
LOCAL_STATIC_LIBRARIES	:= openssl_crypto

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../openssl-lib/android/include \
	$(LOCAL_PATH)/cc7

# Multi-platform sources
# cc7 core
LOCAL_SRC_FILES := \
	cc7/detail/StringUtils.cpp \
	cc7/DebugFeatures.cpp \
	cc7/ByteRange.cpp \
	cc7/ByteArray.cpp \
	cc7/Base32.cpp \
	cc7/Base64.cpp \
	cc7/HexString.cpp \
	cc7/BaseException.cpp \
	cc7/Time.cpp

# cc7/utils
LOCAL_SRC_FILES += \
	cc7/utils/DataReader.cpp \
	cc7/utils/DataWriter.cpp \
	cc7/utils/URLEncoding.cpp

# cc7/crypto
LOCAL_SRC_FILES += \
	cc7/crypto/detail/OSSLObjects.cpp \
	cc7/crypto/CryptoPrivate.cpp \
	cc7/crypto/CryptoConstants.cpp \
	cc7/crypto/Random.cpp \
	cc7/crypto/Cipher.cpp \
	cc7/crypto/Key.cpp \
	cc7/crypto/KeyPair.cpp \
	cc7/crypto/SymmetricKey.cpp \
	cc7/crypto/MAC.cpp \
	cc7/crypto/MessageDigest.cpp \
	cc7/crypto/Signature.cpp \
	cc7/crypto/KeyAgreement.cpp \
	cc7/crypto/KeyEncapsulation.cpp \
	cc7/crypto/KeyDerivation.cpp \
	cc7/crypto/AEAD.cpp \
	cc7/crypto/Parameter.cpp \
	cc7/crypto/NonceGenerator.cpp

# cc7/crypto/alg
LOCAL_SRC_FILES += \
	cc7/crypto/alg/AES.cpp \
	cc7/crypto/alg/HMAC.cpp \
	cc7/crypto/alg/KMAC.cpp \
	cc7/crypto/alg/MACBase.cpp \
	cc7/crypto/alg/SHA.cpp \
	cc7/crypto/alg/MLDSA.cpp \
	cc7/crypto/alg/MLKEM.cpp \
	cc7/crypto/alg/DHKEM.cpp \
	cc7/crypto/alg/ECDSA.cpp \
	cc7/crypto/alg/ECDH.cpp \
	cc7/crypto/alg/ECKeyPair.cpp \
	cc7/crypto/alg/KeyUtility.cpp \
	cc7/crypto/alg/X963KDF.cpp \
	cc7/crypto/alg/NullKDF.cpp \
	cc7/crypto/alg/PBKDF2.cpp

# cc7/json
LOCAL_SRC_FILES += \
	cc7/json/JsonValue.cpp \
	cc7/json/JsonReader.cpp \
	cc7/json/JsonWriter.cpp \
	cc7/json/JsonException.cpp

# cc7/jwt
LOCAL_SRC_FILES += \
	cc7/jwt/JwsSpec.cpp \
	cc7/jwt/JwsKey.cpp \
	cc7/jwt/JwsAlgorithm.cpp \
	cc7/jwt/JwsBaseAlgorithm.cpp \
	cc7/jwt/JwsDsaSignature.cpp \
	cc7/jwt/JwsMacSignature.cpp \
	cc7/jwt/JwtException.cpp \
	cc7/jwt/JwtHeader.cpp \
	cc7/jwt/JwtWriter.cpp \
	cc7/jwt/JwtReader.cpp
	
# Android specific sources
LOCAL_SRC_FILES += \
	cc7/platform/android/PlatformAndroid.cpp \
	cc7/platform/android/JniHelper.cpp

include $(BUILD_STATIC_LIBRARY)

# -------------------------------------------------------------------------
# CC7 Tests
# -------------------------------------------------------------------------

include $(CLEAR_VARS)

NDK_TOOLCHAIN_VERSION := clang

# Library name
LOCAL_MODULE			:= libcc7tests
LOCAL_CFLAGS			:= $(EXTERN_CFLAGS)
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -std=c++17 -frtti
LOCAL_CPP_FEATURES		+= exceptions
LOCAL_STATIC_LIBRARIES	:= cc7

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../openssl-lib/android/include \
	$(LOCAL_PATH)/cc7tests

# Testing core
LOCAL_SRC_FILES := \
	cc7tests/TestManager.cpp \
	cc7tests/UnitTest.cpp \
	cc7tests/TestLog.cpp \
	cc7tests/TestFile.cpp \
	cc7tests/TestDirectory.cpp \
	cc7tests/TestResource.cpp \
	cc7tests/PerformanceTimer.cpp

# Testing core (Android)
LOCAL_SRC_FILES += \
	cc7tests/platform/PerformanceTimerAndroid.cpp

# Unit tests (TestCore)
LOCAL_SRC_FILES += \
	cc7tests/tests/cc7base/tt7Testception.cpp

# Unit tests (cc7)
LOCAL_SRC_FILES += \
	cc7tests/tests/EmbeddedTestsList.cpp \
	cc7tests/tests/cc7base/cc7Base32Tests.cpp \
	cc7tests/tests/cc7base/cc7Base64Tests.cpp \
	cc7tests/tests/cc7base/cc7ByteArrayTests.cpp \
	cc7tests/tests/cc7base/cc7ByteRangeTests.cpp \
	cc7tests/tests/cc7base/cc7HexStringTests.cpp \
	cc7tests/tests/cc7base/cc7PlatformTests.cpp

# Unit tests (cc7/json)
LOCAL_SRC_FILES += \
	cc7tests/tests/cc7json/JsonReaderTests.cpp \
	cc7tests/tests/cc7json/JsonWriterTests.cpp \
	cc7tests/tests/cc7json/JsonValueTests.cpp

# Unit tests (cc7/jwt)
LOCAL_SRC_FILES += \
	cc7tests/tests/cc7jwt/JwtTests.cpp

# Unit tests (cc7/utils)
LOCAL_SRC_FILES += \
	cc7tests/tests/cc7utils/DataWriterReaderTests.cpp \
	cc7tests/tests/cc7utils/URLEncodingTests.cpp

# Unit tests (cc7/crypto)
LOCAL_SRC_FILES += \
	cc7tests/tests/cc7crypto/CipherTests.cpp \
	cc7tests/tests/cc7crypto/AEADTests.cpp \
	cc7tests/tests/cc7crypto/ImportKeyTests.cpp \
	cc7tests/tests/cc7crypto/KeyAgreementTests.cpp \
	cc7tests/tests/cc7crypto/KeyEncapsulationTests.cpp \
	cc7tests/tests/cc7crypto/KeyDerivationTests.cpp \
	cc7tests/tests/cc7crypto/MACTests.cpp \
	cc7tests/tests/cc7crypto/MessageDigestTests.cpp \
	cc7tests/tests/cc7crypto/SignatureTests.cpp \
	cc7tests/tests/cc7crypto/NonceGeneratorTests.cpp

# Unit tests (OpenSSL)
LOCAL_SRC_FILES += \
	cc7tests/tests/openssl/cc7OpenSSLIntegration.cpp

# Generated files
LOCAL_SRC_FILES += \
	cc7tests/tests/test-data.generated/g_testFiles.cpp


include $(BUILD_STATIC_LIBRARY)
