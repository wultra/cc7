# -----------------------------------------------------------------------------
# Archive file, remote URL and local path

OPENSSL_ARCHIVE_FILE="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_ARCHIVE_BASE_URL="https://github.com/openssl/openssl/releases/download"
OPENSSL_ARCHIVE_LOCAL_PATH="${OPENSSL_DEST}/${OPENSSL_ARCHIVE_FILE}"

# OpenSSL features

OPENSSL_CONF_PARAMS=" no-deprecated no-filenames no-shared no-sock no-tls no-ssl no-ssl3 no-ui-console no-engine no-comp no-ts no-ocsp no-async no-tests"
OPENSSL_CONF_PARAMS+=" no-idea no-camellia no-seed no-bf no-cast no-des no-rc2 no-rc4 no-rc5 no-md2 no-md4 no-dsa no-dh no-rfc3779"
OPENSSL_CONF_PARAMS+=" no-whirlpool no-srp no-mdc2 no-srtp no-aria no-ct no-gost no-poly1305 no-sm2 no-sm3 no-sm4"
OPENSSL_CONF_PARAMS+=" no-scrypt no-blake2 no-siphash"

# Include specific supported API version if is set
[[ -n "$OPENSSL_API_VERSION" ]] && OPENSSL_CONF_PARAMS+=" --api=$OPENSSL_API_VERSION"

# -----------------------------------------------------------------------------
# Apple specific
#  - Note that we don't build all architectures and platforms. 
#    The following lists exclude watchOS and macOSX variants from the build.

APPLE_PLATFORMS="watchOS watchOS_Simulator iOS iOS_Simulator macOS_Catalyst tvOS tvOS_Simulator"
APPLE_REF_PLATFORM="iOS"
APPLE_TARGETS="ios-sim-cross-x86_64 ios-sim-cross-arm64"
APPLE_TARGETS+=" ios64-cross-arm64"
APPLE_TARGETS+=" mac-catalyst-x86_64 mac-catalyst-arm64"
APPLE_TARGETS+=" tvos-sim-cross-x86_64 tvos-sim-cross-arm64"
APPLE_TARGETS+=" tvos64-cross-arm64"
APPLE_TARGETS+=" watchos-sim-cross-arm64 watchos-sim-cross-x86_64"
APPLE_TARGETS+=" watchos-cross-arm64_32 watchos-cross-armv7k"
# APPLE_TARGETS+=" macos64-x86_64 macos64-arm64"

# Minimum system versions
APPLE_IOS_MIN_SDK="13.0"
APPLE_TVOS_MIN_SDK="13.0"
APPLE_CATALYST_MIN_SDK="13.0"
APPLE_WATCHOS_MIN_SDK="4.0"
APPLE_OSX_MIN_SDK="11.0"

# -----------------------------------------------------------------------------
# Android specific

ANDROID_ARCHITECTURES="armeabi-v7a arm64-v8a x86 x86_64" 
ANDROID_API_LEVEL_32="21"   # LTS NDK r27 supports API lvl 21+
ANDROID_API_LEVEL_64="21"	# 64-bits were introduced in API lvl 21

# -----------------------------------------------------------------------------
# Other params

BUILD_JOBS_COUNT=$(getconf _NPROCESSORS_ONLN)
CC7_RELEASE_URL="https://github.com/wultra/cc7/releases"