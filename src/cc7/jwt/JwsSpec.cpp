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

#include "JwsSpec.h"

#include <cc7/jwt/JwtException.h>
#include <cc7/utils/DataReader.h>
#include <cc7/utils/DataWriter.h>

namespace cc7 {
namespace jwt {

static ByteArray EC_JoseToAsn1(const JwsSpec* spec, const ByteRange& signature);
static ByteArray EC_Asn1ToJose(const JwsSpec* spec, const ByteRange& signature);

static const std::string NIL;

static const std::vector<JwsSpec> spec_list {
    // RFC-7515
    
    // HMAC-SHA based
    { JwsSpec::Type::MAC, "HS256", "HMAC-SHA-256", NIL, 0, "", nullptr, nullptr },
    { JwsSpec::Type::MAC, "HS384", "HMAC-SHA-384", NIL, 0, "", nullptr, nullptr },
    { JwsSpec::Type::MAC, "HS512", "HMAC-SHA-512", NIL, 0, "", nullptr, nullptr },
    // ECDSA based
    { JwsSpec::Type::DSA, "ES256", "ECDSA-SHA-256", "P-256", 32, "", EC_JoseToAsn1, EC_Asn1ToJose },
    { JwsSpec::Type::DSA, "ES384", "ECDSA-SHA-384", "P-384", 48, "", EC_JoseToAsn1, EC_Asn1ToJose },
    { JwsSpec::Type::DSA, "ES512", "ECDSA-SHA-512", "P-521", 66, "", EC_JoseToAsn1, EC_Asn1ToJose },
    
    // Draft algorithms
    
    // ML-DSA
    { JwsSpec::Type::DSA, "ML-DSA-44", "ML-DSA-44", "ML-DSA-44", 0, "", nullptr, nullptr },
    { JwsSpec::Type::DSA, "ML-DSA-65", "ML-DSA-65", "ML-DSA-65", 0, "", nullptr, nullptr },
    { JwsSpec::Type::DSA, "ML-DSA-87", "ML-DSA-87", "ML-DSA-87", 0, "", nullptr, nullptr },
    // KMAC based
    { JwsSpec::Type::MAC, "xKMAC128", "KMAC-128", NIL, 32, "JWS", nullptr, nullptr },
    { JwsSpec::Type::MAC, "xKMAC256", "KMAC-256", NIL, 64, "JWS", nullptr, nullptr },
};

const JwsSpec* JwsSpec::specForJwsAlgorithm(const std::string& jws_algorithm)
{
    for (auto& spec : spec_list) {
        if (spec.jwsName == jws_algorithm) {
            return &spec;
        }
    }
    return nullptr;
}

const JwsSpec* JwsSpec::specForKeyAlgorithm(const std::string& key_algorithm)
{
    for (auto& spec : spec_list) {
        if (spec.keyType == key_algorithm) {
            return &spec;
        }
    }
    return nullptr;
}


// MARK: - EC adapter routines

static cc7::ByteArray _SkipPaddingBytes(const cc7::ByteRange & r)
{
    cc7::ByteArray out;
    size_t offset = 0, size = r.size();
    while (offset != size) {
        if (r[offset] != 0) {
            break;
        }
        ++offset;
    }
    // If the encoded number is negative, then keep zero byte as prefix.
    if (r[offset] > 0x7F) {
        if (offset == 0) {
            // We're already at the beginning of range, so prepend zero before the sequence
            out.push_back(0);
        } else {
            // Offset is greater than 0, so we can copy zero from the padding
            offset--;
        }
    }
    out.append(r.subRangeFrom(offset));
    return out;
}

static cc7::ByteArray _EncodeAsn1ByteSequence(utils::DataWriter & writer, const cc7::ByteRange & bytes)
{
    writer.reset();
    writer.writeByte(0x02);
    writer.writeAsn1Count(bytes.size());
    writer.writeMemory(bytes);
    return writer.serializedData();
}

static ByteArray EC_JoseToAsn1(const JwsSpec* spec, const ByteRange& signature)
{
    const auto param_size = spec->sizeParam;
    
    if (signature.size() != param_size * 2) {
        throw JwtException("Wrong JWS signature size");
    }
    // Split input data into half and skip zero leading bytes for each parameter.
    auto R = _SkipPaddingBytes(signature.subRangeTo(param_size));
    auto S = _SkipPaddingBytes(signature.subRangeFrom(param_size));
    
    auto writer = utils::DataWriter();
    auto encoded_R = _EncodeAsn1ByteSequence(writer, R);
    auto encoded_S = _EncodeAsn1ByteSequence(writer, S);
    // Encode the whole sequence
    writer.reset();
    writer.writeByte(0x30);
    writer.writeAsn1Count(encoded_R.size() + encoded_S.size());
    writer.writeMemory(encoded_R);
    writer.writeMemory(encoded_S);
    return writer.serializedData();
}

static bool _DecodeAsn1ByteSequence(utils::DataReader & reader, cc7::ByteRange & out_data, size_t param_size, size_t & out_size)
{
    cc7::byte tmp;
    if (!reader.readByte(tmp) || tmp != 0x02) {
        // Invalid sequence header
        return false;
    }
    if (!reader.readAsn1Count(out_size)) {
        // Invalid size
        return false;
    }
    if (out_size > param_size + 1) {
        // Too big
        return false;
    }
    return reader.readMemoryRange(out_data, out_size);
}

static void _ThrowWrongAsn1 [[noreturn]]()
{
    throw std::logic_error("Wrong ASN.1 sequence");
}

static ByteArray EC_Asn1ToJose(const JwsSpec* spec, const ByteRange& signature)
{
    const auto param_size = spec->sizeParam;
    
    cc7::ByteArray out;
    auto reader = utils::DataReader(signature, false);
    
    cc7::byte tmp;
    // Read first byte (sequence)
    if (!reader.readByte(tmp) || tmp != 0x30) {
        _ThrowWrongAsn1();
    }
    size_t sign_length, r_length, s_length;
    cc7::ByteRange R, S;
    if (!reader.readAsn1Count(sign_length)) {
        _ThrowWrongAsn1();
    }
    // Overall length should match DER length - offset
    if (sign_length != signature.size() - reader.currentOffset()) {
        _ThrowWrongAsn1();
    }
    // Read R.
    if (!_DecodeAsn1ByteSequence(reader, R, param_size, r_length)) {
        _ThrowWrongAsn1();
    }
    // Read S.
    if (!_DecodeAsn1ByteSequence(reader, S, param_size, s_length)) {
        _ThrowWrongAsn1();
    }
    
    // Everything looks fine. Now construct JOSE signature.
    out.reserve(2 * param_size);
    
    // Append R
    if (r_length > param_size) {
        out.append(R.subRangeFrom(r_length - param_size));
    } else {
        if (r_length < param_size) {
            out.append(param_size - r_length, 0);
        }
        out.append(R);
    }
    // Append S
    if (s_length > param_size) {
        out.append(S.subRangeFrom(s_length - param_size));
    } else {
        if (s_length < param_size) {
            out.append(param_size - s_length, 0);
        }
        out.append(S);
    }
    return out;
}


} // namespace jwt
} // namespace cc7
