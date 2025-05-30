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

#include <cc7/jwt/JwtException.h>

namespace cc7 {
namespace jwt {

class JwtHeader
{
public:
    
    JwtHeader();
    JwtHeader(const std::string& algorithm, const std::string& type = JWT_TYPE);
    
    const std::string& getEncoded();
    
    void setAlgorithm(const std::string& algorithm);
    const std::string& getAlgorithm() const;
    void setType(const std::string& type);
    const std::string& getType() const;
    
    bool isValid() const;
    bool isSupportedAlgorithm() const;
    
    static JwtHeader fromEncodedString(const std::string& encoded);
    
    static const std::string JWT_TYPE;
    
private:
    
    JwtHeader(const std::string& algorithm, const std::string& type, const std::string& encoded);
    
    std::string _type;
    std::string _algorithm;
    std::string _encoded;
};

} // namespace jwt
} // namespace cc7
