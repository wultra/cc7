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

#include <cc7/jwt/JwtKey.h>
#include <cc7/jwt/JwtHeader.h>
#include <cc7/json/Json.h>

namespace cc7 {
namespace jwt {

class JwtReader
{
public:
    JwtReader(const JwtReader& other) = default;
    JwtReader(JwtReader&& other) = default;
    JwtReader& operator=(const JwtReader&) = default;
    JwtReader& operator=(JwtReader&&) = default;
    
    // Build
    
    static JwtReader fromCompact(const std::string& jwt);
    static JwtReader fromJson(const json::JsonValue& value);
    static JwtReader fromJsonData(const ByteRange& data);
    static JwtReader fromJsonString(const std::string& string);
    
    // Verify
    
    JwtReader& verify(const JwtKeyList& keys);
    
    bool isCompact() const;
    const ByteArray& getPayload() const;
    const std::vector<JwtHeader>& getHeaders() const;
    
private:
    
    JwtReader(const std::vector<JwtHeader>& headers,
              const std::vector<ByteArray>& signatures,
              const ByteArray& payload,
              const std::string& _encoded_payload);
    
    ByteArray _payload;
    std::string _encoded_payload;
    
    std::vector<JwtHeader> _headers;
    std::vector<ByteArray> _signatures;
};

} // namespace jwt
} // namespace cc7
