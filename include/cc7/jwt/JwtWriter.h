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

#include <cc7/jwt/JwsAlgorithm.h>
#include <cc7/jwt/JwtHeader.h>
#include <cc7/json/Json.h>

namespace cc7 {
namespace jwt {

class JwtWriter
{
public:
    JwtWriter(int json_options = json::JsonWriter::Default);
    
    // Building
    
    JwtWriter& withJsonPayload(const json::JsonValue& payload, const std::string & payload_type = JwtHeader::NO_TYPE);
    JwtWriter& withPayload(const ByteRange& payload, const std::string & payload_type = JwtHeader::NO_TYPE);
    JwtWriter& withHeader(const JwtHeader& header);
    JwtWriter& sign(const JwsKeyList& keys,
                    const JwsAlgorithmProvider& provider = JwsAlgorithmProvider::defaultProvider);
    
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
    std::string _payload_type;
    
    json::JsonWriter _writer;
    
    static std::string signPayload(const JwsKey& key,
                                   const std::string& payload,
                                   const JwsAlgorithmProvider& provider,
                                   JwtHeader& out_header);
};

} // namespace jwt
} // namespace cc7
