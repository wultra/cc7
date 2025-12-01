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

#include <cc7/jwt/JwtReader.h>
#include <cc7/Base64.h>
#include <cc7/detail/StringUtils.h>
#include "JwsBaseAlgorithm.h"

namespace cc7::jwt {

static const std::string cDOT(".");

JwtReader::JwtReader(const std::vector<JwtHeader>& headers,
                     const std::vector<ByteArray>& signatures,
                     const ByteArray& payload,
                     const std::string& encoded_payload) :
    _headers(headers),
    _signatures(signatures),
    _payload(payload),
    _encoded_payload(encoded_payload)
{
}

JwtReader JwtReader::fromCompact(const std::string &jwt)
{
    try {
        auto elements = detail::SplitString(jwt, '.', false);
        if (elements.size() != 3) {
            throw JwtException("String is not JWT");
        }
        const auto& header_data = elements[0];
        const auto& encoded_payload = elements[1];
        auto signature = Base64::urlDecode(elements[2]);
        auto header = JwtHeader::fromEncodedString(header_data);
        if (!header.isValid()) {
            throw JwtException("Invalid JWT header");
        }
        auto payload = Base64::urlDecode(encoded_payload);
        return JwtReader({ header }, { signature }, payload, encoded_payload);
    } catch (std::exception & e) {
        throw JwtException("Failed to build JWT reader from string", std::current_exception());
    }
}

JwtReader JwtReader::fromJson(const json::JsonValue &value)
{
    try {
        auto encoded_payload = value["payload"].asString();
        auto payload = Base64::urlDecode(encoded_payload);
        std::vector<JwtHeader> headers;
        std::vector<ByteArray> signatures;
        for (const auto& item : value["signatures"].asArray()) {
            auto header = JwtHeader::fromEncodedString(item["protected"].asString());
            if (!header.isValid()) {
                throw JwtException("Invalid JWT header");
            }
            auto signature = Base64::urlDecode(item["signature"].asString());
            headers.push_back(header);
            signatures.push_back(signature);
        }
        return JwtReader(headers, signatures, payload, encoded_payload);
    } catch (std::exception & e) {
        throw JwtException("Failed to build JWT reader from JsonValue", std::current_exception());
    }
}

JwtReader JwtReader::fromJsonData(const ByteRange& data)
{
    auto root = json::JsonReader().fromJsonData(data);
    return fromJson(root);
}

JwtReader JwtReader::fromJsonString(const std::string& string)
{
    auto root = json::JsonReader().fromJsonString(string);
    return fromJson(root);
}

const JwtReader& JwtReader::verify(const JwsKeyList& keys, JwsVerifyMode mode, const JwsAlgorithmProvider& provider) const
{
    if (keys.empty()) {
        throw std::invalid_argument("Empty list of keys");
    }
    std::set<std::string> processed;
    size_t matched = 0;
    for (auto i = 0; i < _headers.size(); i++) {
        auto& header = _headers[i];
        const auto& signature = _signatures[i];
        const auto& algorithm = header.getAlgorithm();
        if (processed.find(algorithm) != processed.end()) {
            throw JwtException("Duplicate signature for algorithm " + algorithm);
        }
        processed.insert(algorithm);
        
        // Look for key
        auto key_found = std::find_if(keys.begin(), keys.end(), [algorithm](const JwsKeyPtr& ptr) {
            return ptr->getJwtAlgorithm() == algorithm;
        });
        if (key_found == keys.end()) {
            if (mode == JwsVerifyMode::VERIFY_ALL_SIGNATURES) {
                throw JwtException("Missing key for algorithm " + algorithm);
            }
            // VERIFY_ALL_KEYS or VERIFY_AT_LEAST_ONE is specified and no key for verify found.
            // This may be OK, so continue with another signature
            continue;
        }
        auto key = *key_found;
        auto verifier = provider.getAlgorithm(algorithm);
        bool success = false;
        try {
            auto data = header.getEncoded() + cDOT + _encoded_payload;
            success = verifier->verify(*key, MakeRange(data), signature);
        } catch (std::exception& e) {
            throw JwtException("Signature verify failed " + algorithm, std::current_exception());
        }
        if (!success) {
            throw JwtException("Signature doesn't match " + algorithm);
        }
        matched++;
    }
    if (!matched) {
        throw JwtException("No signature verified");
    }
    if (matched != keys.size()) {
        if (mode == JwsVerifyMode::VERIFY_ALL_KEYS) {
            // Number of verified signatures doesn't match the number of provided keys.
            throw JwtException("Not all keys used for signature verification");
        }
    }
    return *this;
}

bool JwtReader::isCompact() const
{
    return _headers.size() <= 1;
}

const ByteArray& JwtReader::getPayload() const
{
    return _payload;
}

const std::vector<JwtHeader>& JwtReader::getHeaders() const
{
    return _headers;
}

} // namespace cc7::jwt
