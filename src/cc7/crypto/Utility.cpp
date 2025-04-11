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

#include <cc7/crypto/Utility.h>
#include <openssl/rand.h>

#if defined(CC7_APPLE) || defined(CC7_ANDROID)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace cc7
{
namespace crypto
{

// MARK: - Random generator

#if defined(CC7_APPLE) || defined(CC7_ANDROID)

static bool GetBytesFromSystemGenerator(ByteArray & buffer)
{
    int fd = open("/dev/urandom", O_RDONLY);
    bool result = false;
    if (fd >= 0) {
        ssize_t readed = read(fd, buffer.data(), buffer.size());
        result = readed == buffer.size();
        close(fd);
    }
    return result;
}

#else
#error Unsupported platform
#endif

// MARK: - Public functions

ByteArray GetRandomData(size_t size, bool reject_sequence_of_zeros)
{
    cc7::ByteArray data(size, 0);
    cc7::ByteArray zeros;
    size_t attempts = 16;
    while (size > 0) {
        int rc = RAND_bytes(data.data(), (int)size);
        if (rc != 1 || attempts == 0) {
            throw std::domain_error("Failed to generate random data");
        }
        if (!reject_sequence_of_zeros) {
            break;
        }
        if (zeros.size() != size) {
            zeros.assign(size, 0);
        }
        if (data != zeros) {
            break;
        }
        --attempts;
    }
    return data;
}

ByteArray GetUniqueRandomData(size_t size, const std::vector<ByteRange> & reject_byte_sequences)
{
    cc7::ByteArray data(size, 0);
    size_t attempts = 16;
    while (size > 0) {
        int rc = RAND_bytes(data.data(), (int)size);
        if (rc != 1 || attempts == 0) {
            throw std::domain_error("Failed to generate random data");
        }
        bool unique = true;
        for (auto && other_data : reject_byte_sequences) {
            if (data.byteRange() == other_data) {
                unique = false;
                break;
            }
        }
        if (unique) {
            break;
        }
        --attempts;
    }
    return data;
}

void ReseedRandomGenerator()
{
    static bool s_initial_seed = true;
    size_t nbytes;
    if (s_initial_seed) {
        // This is an initial seed. The recommended size for OpenSSL's PRNG is 1024 bytes
        s_initial_seed = false;
        nbytes = 1024;
    } else {
        // All subsequent re-seeds may be shorter.
        unsigned char count = 16;
        RAND_bytes(&count, sizeof(unsigned char));
        if (count < 16) {
            count = 16;
        } else if (count > 64) {
            count = 64;
        }
        nbytes = count;
    }
    
    cc7::ByteArray buffer(nbytes, 0);
    if (!GetBytesFromSystemGenerator(buffer)) {
        throw std::domain_error("Failed to get random data from system generator");
    }
    RAND_seed(buffer.data(), (int)buffer.size());
}

} // cc7::crypto
} // cc74
