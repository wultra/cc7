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

#include <cc7/jwt/JwsKey.h>

namespace cc7::jwt {

class JwsAlgorithm : public BaseObject
{
public:
    virtual ByteArray sign(const JwsKey& key, const ByteRange& data) const = 0;
    virtual bool verify(const JwsKey& key, const ByteRange& data, const ByteRange& signature) const = 0;
};

CC7_SHARED_PTR(JwsAlgorithm)

class JwsAlgorithmProvider : public BaseObject
{
public:
    virtual JwsAlgorithmPtr getAlgorithm(const std::string& algorithm_name) const;
    
    static const JwsAlgorithmProvider defaultProvider;
};

CC7_SHARED_PTR(JwsAlgorithmProvider)

} // namespace cc7::jwt
