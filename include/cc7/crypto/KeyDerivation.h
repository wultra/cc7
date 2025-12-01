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

namespace cc7::crypto {

class KeyDerivation : public Algorithm
{
public:
    
    virtual cc7::ByteArray deriveKeyBytes(const ByteRange & key_material,
                                          const ParameterList & parameters = {}) const = 0;
    
    SymmetricKeyPtr deriveKey(const ByteRange & key_material,
                              const ParameterList & parameters = {}) const;

    SymmetricKeyPtr deriveKey(const SymmetricKey & key,
                              const std::string & out_key_type,
                              const ParameterList & parameters = {}) const;

    static std::shared_ptr<KeyDerivation> getInstance(const std::string & algorithm);
    
    static std::shared_ptr<KeyDerivation> noDerivation();
};

CC7_SHARED_PTR(KeyDerivation)

} // namespace cc7::crypto
