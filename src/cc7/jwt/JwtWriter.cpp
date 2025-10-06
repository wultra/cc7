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

#include <cc7/jwt/JwtWriter.h>
#include <cc7/Base64.h>
#include "JwsBaseAlgorithm.h"

namespace cc7 {
namespace jwt {

static const std::string cDOT(".");

JwtWriter::JwtWriter(int options) :
    _compact(false),
    _has_payload(false),
    _writer(options)
{
}

JwtWriter& JwtWriter::withJsonPayload(const json::JsonValue &payload, const std::string& payload_type)
{
    return withPayload(_writer.toJsonData(payload), payload_type);
}

JwtWriter& JwtWriter::withPayload(const ByteRange &payload, const std::string& payload_type)
{
    if (_has_payload) {
        throw JwtException("Payload is already set");
    }
    _has_payload = true;
    _payload = payload;
    _payload_type = payload_type;
    return *this;
}

JwtWriter& JwtWriter::withHeader(const JwtHeader &header)
{
    if (!_headers.empty()) {
        throw JwtException("Header is already set");
    }
    _headers.push_back(header);
    _compact = true;
    return *this;
}

JwtWriter& JwtWriter::sign(const JwsKeyList &keys, const JwsAlgorithmProvider& provider)
{
    if (keys.empty()) {
        throw std::invalid_argument("Empty list of keys");
    }
    if (!_headers.empty()) {
        throw JwtException("Cannot sign because header is set");
    }
    auto payload = getEncodedPayload();
    for (auto& key : keys) {
        JwtHeader header;
        if (!_payload_type.empty()) {
            header.setType(_payload_type);
        }
        auto signature = signPayload(*key, payload, provider, header);
        _headers.push_back(header);
        _signatures.push_back(signature);
    }
    _compact = _headers.size() == 1;
    return *this;
}

std::string JwtWriter::toCompact()
{
    if (!_compact) {
        throw JwtException("JWT cannot be represented as compact string");
    }
    if (_headers.empty()) {
        throw JwtException("JWT header is not set");
    }
    auto header = _headers.front().getEncoded(); // TODO: breaks const rule
    auto payload = getEncodedPayload();
    auto signature = _signatures.empty() ? std::string() : _signatures.front();
    return header + cDOT + payload + cDOT + signature;
}

json::JsonValue JwtWriter::toJson()
{
    auto signatures = json::JsonValue::array();
    auto& array = signatures.asMutableArray();
    
    if (_headers.empty()) {
        throw JwtException("JWT header is not set");
    }
    if (_signatures.empty()) {
        throw JwtException("No signature is set");
    }
    if (_signatures.size() != _headers.size()) {
        throw std::logic_error("Number of headers doesn't match signatures");
    }
    for (auto i = 0; i < _headers.size(); i++) {
        auto entry = json::JsonValue::object();
        entry["protected"] = json::JsonValue(_headers[i].getEncoded());
        entry["signature"] = json::JsonValue(_signatures[i]);
        array.push_back(entry);
    }
    auto result = json::JsonValue::object();
    result["payload"]    = json::JsonValue(getEncodedPayload());
    result["signatures"] = signatures;
    return result;
}

std::string JwtWriter::toJsonString()
{
    return _writer.toString(toJson());
}

cc7::ByteArray JwtWriter::toJsonData()
{
    return _writer.toData(toJson());
}

std::string JwtWriter::getEncodedPayload() const
{
    if (!_has_payload) {
        throw JwtException("Payload is not set");
    }
    return _payload.base64Url();
}

const ByteArray& JwtWriter::getPayload() const
{
    return _payload;
}

// MARK: - Common

bool JwtWriter::isCompact() const
{
    return _headers.size() <= 1;
}

// MARK: - Private


std::string JwtWriter::signPayload(const JwsKey &key,
                                   const std::string& payload,
                                   const JwsAlgorithmProvider& provider,
                                   JwtHeader& out_header)
{
    out_header.setAlgorithm(key.getJwtAlgorithm());
    auto algorithm = provider.getAlgorithm(out_header.getAlgorithm());
    auto data_to_sign = out_header.getEncoded() + cDOT + payload;
    auto signature = algorithm->sign(key, MakeRange(data_to_sign));
    return signature.base64Url();
}

} // namespace jwt
} // namespace cc7
