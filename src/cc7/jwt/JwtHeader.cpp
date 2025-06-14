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

#include <cc7/jwt/JwtHeader.h>
#include <cc7/json/Json.h>
#include <cc7/Base64.h>
#include "JwsSpec.h"

namespace cc7 {
namespace jwt {

const std::string JwtHeader::JWT_TYPE("JWT");

JwtHeader::JwtHeader() :
    _type(JWT_TYPE)
{
}

JwtHeader::JwtHeader(const std::string& algorithm, const std::string& type) :
    _algorithm(algorithm),
    _type(type)
{
}

JwtHeader::JwtHeader(const std::string& algorithm, const std::string& type, const std::string& encoded) :
    _algorithm(algorithm),
    _type(type),
    _encoded(encoded)
{
}

bool JwtHeader::isValid() const
{
    return !_algorithm.empty();
}

const std::string& JwtHeader::getEncoded()
{
    if (!isValid()) {
        throw JwtException("Header is not valid");
    }
    if (_encoded.empty()) {
        auto object = json::JsonValue::object();
        if (!_type.empty()) {
            object["typ"] = json::JsonValue(_type);
        }
        if (!_algorithm.empty()) {
            object["alg"] = json::JsonValue(_algorithm);
        }
        _encoded = Base64::urlEncode(json::JsonWriter().toData(object));
    }
    return _encoded;
}

void JwtHeader::setType(const std::string &type)
{
    _type = type;
    _encoded.clear();
}

const std::string& JwtHeader::getType() const
{
    return _type;
}

void JwtHeader::setAlgorithm(const std::string& algorithm)
{
    _algorithm = algorithm;
    _encoded.clear();
}

const std::string& JwtHeader::getAlgorithm() const
{
    return _algorithm;
}

bool JwtHeader::isSupportedAlgorithm() const
{
    if (!_algorithm.empty()) {
        return JwsSpec::specForJwsAlgorithm(_algorithm) != nullptr;
    }
    return false;
}

JwtHeader JwtHeader::fromEncodedString(const std::string& encoded)
{
    try {
        auto header_data = Base64::urlDecode(encoded);
        auto hdr = json::JsonReader().parse(header_data).asObject();
        std::string algorithm, type;
        auto found = hdr.find("alg");
        if (found != hdr.end()) {
            algorithm = found->second.asString();
        }
        found = hdr.find("typ");
        if (found != hdr.end()) {
            type = found->second.asString();
        }
        return JwtHeader(algorithm, type, encoded);
    } catch (std::exception & e) {
        throw JwtException("Failed to decode JWT header", std::current_exception());
    }
}

} // namespace jwt
} // namespace cc7
