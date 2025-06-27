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

#include <cc7/crypto/Algorithm.h>
#include <cc7/crypto/SymmetricKey.h>

namespace cc7 {
namespace crypto {

class MAC : public Algorithm
{
public:
    
    virtual ByteArray token(const ByteRange & key,
                            const ByteRange & data,
                            const ParameterList & parameters = {}) const = 0;
    
    bool verifyToken(const ByteRange & key,
                     const ByteRange & data,
                     const ByteRange & token,
                     const ParameterList & parameters = {}) const
    {
        auto our_token = this->token(key, data, parameters);
        return ConstTimeEqual(token, our_token);
    }
        
    /// Get instnace of MAC algorithm.
    ///
    /// The following algorithms are supported:
    /// - HMAC-SHA-256
    /// - HMAC-SHA-384
    /// - HMAC-SHA-512
    /// - HMAC-SHA3-256
    /// - HMAC-SHA3-384
    /// - HMAC-SHA3-512
    /// - KMAC-128
    /// - KMAC-256
    ///
    /// - Parameter algorithm: Algorithm identifier.
    static std::shared_ptr<MAC> getInstance(const std::string & algorithm);
};

CC7_SHARED_PTR(MAC)

} // cc7::crypto
} // cc7
