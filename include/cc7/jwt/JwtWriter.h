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

class JwtWriter
{
public:
    JwtWriter(int json_options = json::JsonWriter::Default);
    
    // Building
    
    JwtWriter& withJsonPayload(const json::JsonValue& payload);
    JwtWriter& withPayload(const ByteRange& payload);
    JwtWriter& withHeader(const JwtHeader& header);
    JwtWriter& sign(const JwtKeyList& keys);
    
    // Result
    
    json::JsonValue toJson();
    std::string toJsonString();
    cc7::ByteArray toJsonData();
    std::string toCompact();
    
    // Common getters
    
    bool isCompact() const;
    std::string getEncodedPayload() const;
    const ByteArray& getPayload() const;
    
private:
    
    bool _compact;
    bool _has_payload;
    
    std::vector<JwtHeader>   _headers;
    std::vector<std::string> _signatures;
    
    ByteArray _payload;
    
    json::JsonWriter _writer;
    
    static std::string signPayload(const JwtKey& key, const std::string& payload, JwtHeader& out_header);
};

} // namespace jwt
} // namespace cc7
