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
const std::string JwtHeader::NO_TYPE("");

static const std::string cALG("alg");
static const std::string cTYP("typ");

JwtHeader::JwtHeader()
{
}

JwtHeader::JwtHeader(const std::string& algorithm, const std::string& type) :
    _algorithm(algorithm),
    _type(type)
{
}

bool JwtHeader::isValid() const noexcept
{
    return !_algorithm.empty();
}

std::string JwtHeader::getEncoded() const
{
    if (!isValid()) {
        throw JwtException("Header is not valid");
    }
    auto object = json::JsonValue::object();
    if (!_type.empty()) {
        object[cTYP] = json::JsonValue(_type);
    }
    if (!_algorithm.empty()) {
        object[cALG] = json::JsonValue(_algorithm);
    }
    return Base64::urlEncode(json::JsonWriter().toData(object));
}

void JwtHeader::setType(const std::string &type)
{
    _type = type;
}

const std::string& JwtHeader::getType() const noexcept
{
    return _type;
}

void JwtHeader::setAlgorithm(const std::string& algorithm)
{
    _algorithm = algorithm;
}

const std::string& JwtHeader::getAlgorithm() const noexcept
{
    return _algorithm;
}

bool JwtHeader::isSupportedAlgorithm() const noexcept
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
        auto found = hdr.find(cALG);
        if (found != hdr.end()) {
            algorithm = found->second.asString();
        }
        found = hdr.find(cTYP);
        if (found != hdr.end()) {
            type = found->second.asString();
        }
        return JwtHeader(algorithm, type);
    } catch (std::exception & e) {
        throw JwtException("Failed to decode JWT header", std::current_exception());
    }
}

} // namespace jwt
} // namespace cc7
