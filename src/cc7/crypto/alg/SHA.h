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

#include <cc7/crypto/MessageDigest.h>
#include "../CryptoPrivate.h"

namespace cc7::crypto {

struct SHASpec
{
    std::string    name;
    const size_t   digest_size;
    const EVP_MD * md;
};

class SHA : public MessageDigest
{
public:

    ByteArray digest(const ByteRange & input, const ParameterList & parameters) const override;
    
    static std::shared_ptr<SHA> getInstance(const std::string & algorithm);
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;
    
private:
        
    const SHASpec * _spec;
    
    SHA(const SHASpec * spec) : _spec(spec) {}
};

} // namespace cc7::crypto
