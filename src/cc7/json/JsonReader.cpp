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

#include <cc7/json/JsonReader.h>
#include <cc7/json/JsonException.h>
#include <cc7/detail/StringUtils.h>

namespace cc7::json {

// MARK: helper functions -

static inline void JSON_ASSERT(bool condition, const char * msg)
{
    if (!condition) {
        throw std::logic_error(msg);
    }
}

void JsonReader::setParserError(const char * reason)
{
    if (_unexpectedEndOfStream || !reason) {
        reason = "Unexpected end of stream";
    }
    size_t line   = _line + 1;
    size_t offset = _offset - _lineBegin + 1 - 1; // -1 due to offset is always one character forward...
    _error  = detail::FormattedString("JSON parser error: %s (line %d, offset %d)", reason, line, offset);
}

// MARK: Stream reading

void JsonReader::resetReader(const ByteRange &range)
{
    _ptr = range.data();
    _offset = 0;
    _length = range.length();
    _line = 0;
    _lineBegin = 0;
    _stack = 0;
    _stackLimit = 16;
    _options = 0;
    _unexpectedEndOfStream = false;
    _consumedSeparator = 0;
    _error.clear();
}

bool JsonReader::isEnd()
{
    return (_offset >= _length) || !_error.empty();
}

const cc7::byte * JsonReader::dataPtr()
{
    return _ptr + _offset;
}

const cc7::byte * JsonReader::dataOffset(size_t offset)
{
    return _ptr + offset;
}

const char * JsonReader::charPtr(size_t offset)
{
    return reinterpret_cast<const char*>(_ptr) + offset;
}


cc7::byte JsonReader::getChar()
{
    JSON_ASSERT(!isEnd(), "End reached or error occured");
    return _ptr[_offset++];
}


const cc7::byte * JsonReader::shouldReadPtr(size_t requiredSize)
{
    JSON_ASSERT(requiredSize > 0, "Required size must be greater than 0");
    if ((_length - _offset) >= requiredSize) {
        // If following check fails then there's a problem in some upper loop.
        // The loop doesn't validate length & offset properly
        JSON_ASSERT(_length > _offset, "Offset is out of range");
        return dataPtr();
    }
    _unexpectedEndOfStream = true;
    return nullptr;
}

void JsonReader::skipCount(size_t count)
{
    _offset += count;
}

void JsonReader::skipBackCount(size_t count)
{
    JSON_ASSERT(count <= _offset, "Wrong count");
    _offset -= count;
}


cc7::byte JsonReader::skipWhitespace()
{
    if (isEnd()) {
        return 0;
    }
    
    do {
        cc7::byte uc = _ptr[_offset++];
        if (!isspace(uc)) {
            return uc;
        }
        if (uc == '\n') {
            _line++;
            _lineBegin = _offset - 1;
        }
    } while (_offset < _length);
    
    return 0;
}


// MARK: Stack & Other

bool JsonReader::pushStack()
{
    _stack++;
    if (_stack < _stackLimit) {
        return true;
    }
    setParserError("The processing stack is too deep");
    return false;
}

bool JsonReader::popStack()
{
    _stack--;
    if (_stack >= 0) {
        return true;
    }
    setParserError("The processing stack underflow.");
    return false;
}


// MARK: Parser -

//
// Parse value
//

JsonValue JsonReader::parseValue(const cc7::byte * allowedSeparators)
{
    _consumedSeparator = 0;
    
    cc7::byte uc = skipWhitespace();
    if (!uc) {
        // regular end
        return json::JsonValue();
    }
    if (uc == '"') {
        //
        // string
        //
        return parseString();
        //
    } else if (uc == '{') {
        //
        // object
        //
        return parseObject();
        //
    } else if (uc == '[') {
        //
        // array
        //
        return parseArray();
        //
    } else if (uc == '-' || (uc >= '0' && uc <= '9')) {
        //
        // number
        //
        return parseNumber();
        //
    } else if (uc == 't') {
        //
        // true
        //
        const cc7::byte * ptr = shouldReadPtr(3);
        if (ptr && ptr[0] == 'r' && ptr[1] == 'u' && ptr[2] == 'e') {
            skipCount(3);
            return JsonValue(true);
        } else {
            setParserError("'true' token is expected");
        }
        //
    } else if (uc == 'f') {
        //
        // false
        //
        const cc7::byte * ptr = shouldReadPtr(4);
        if (ptr && ptr[0] == 'a' && ptr[1] == 'l' && ptr[2] == 's' && ptr[3] == 'e') {
            skipCount(4);
            return JsonValue(false);
        } else {
            setParserError("'false' token is expected");
        }
    } else if (uc == 'n') {
        //
        // null
        //
        const cc7::byte * ptr = shouldReadPtr(3);
        if (ptr && ptr[0] == 'u' && ptr[1] == 'l' && ptr[2] == 'l') {
            skipCount(3);
            return JsonValue(JsonValue::Null);
        } else {
            setParserError("'null' token is expected");
        }
    } else {
        if (allowedSeparators) {
            const cc7::byte * separatorPtr = allowedSeparators;
            while (*separatorPtr) {
                if (*separatorPtr++ == uc) {
                    // returns NaT but without error
                    _consumedSeparator = uc;
                    return JsonValue();
                }
            }
        }
        setParserError("Unexpected character in value");
    }
    
    return JsonValue();
}


//
// Parse array
//

JsonValue JsonReader::parseArray()
{
    if (!pushStack()) {
        return JsonValue();
    }
    
    bool error = false;
    JsonValue array(JsonValue::Array);
    auto & result = array.asMutableArray();
    
    // Process values in array
     const cc7::byte separator[3] = { ',', ']', 0 };
    cc7::byte uc;
    while (1)
    {
        JsonValue value = parseValue(separator + 1);
        if (value.isValid()) {
            result.push_back(value);
        } else {
            if (_consumedSeparator != ']') {
                // Consumed separator must be ']'. This is error, clear result and break loop.
                error = true;
            }
            break;
        }
        
        uc = skipWhitespace();
        if (uc == ',') {
            // Move to next value
            continue;
            
        } else if (uc == ']') {
            // End of array, break loop
            break;
            
        } else {
            if (uc != 0) {
                setParserError("Wrong character in array. Characters ']' or ',' are expected");
            } else {
                setParserError("Unexpected end of array");
            }
            error = true;
        }
        break;
        
    }
    
    popStack();
    
    if (!error) {
        return array;
    }
    return JsonValue();
}

//
// Parse object
//
JsonValue JsonReader::parseObject()
{
    if (!pushStack()) {
        return JsonValue();
    }
    
    bool error = false;
    JsonValue object(JsonValue::Object);
    auto & result = object.asMutableObject();
    
    cc7::byte uc;
    while (1)
    {
        uc = skipWhitespace();
        // '"' or '}' is expected
        if (uc == '"') {
            // Read key
            JsonValue key = parseString();
            if (!key.isType(JsonValue::String)) {
                error = true;
                break;
            }
            // Look for colon
            uc = skipWhitespace();
            if (uc != ':') {
                if (uc != 0) {
                    setParserError("The colon ':' is expected as key-value separator");
                } else {
                    setParserError("Unexpected end of object");
                }
                error = true;
                break;
            }
            // Read value
            JsonValue value =  parseValue(nullptr);
            if (value.isValid()) {
                // store key - value pair
                result[key.asString()] = value;
            } else {
                // something is wrong, break loop.
                // error is already set
                error = true;
                break;
            }
            // Look for ',' or '}'
            uc = skipWhitespace();
            if (uc == ',') {
                // next item in array
                continue;
                
            }
        }
        
        if (uc == '}') {
            // Success, end of object
            break;
        }
        
        if (uc != 0) {
            setParserError("Unknown character in object");
        } else {
            setParserError("Unexpected end of object");
        }
        error = true;
        break;
    }
    
    popStack();
    
    if (!error) {
        return object;
    }
    return JsonValue();
}

//
// Parse string
//

JsonValue JsonReader::parseString()
{
    if (isEnd()) {
        setParserError("Unexpected end of string");
        return JsonValue();
    }
    
    bool error = false;
    ByteArray result;
    cc7::byte uc;
    size_t range_location = _offset;
    size_t range_length   = 0;
    while (!isEnd())
    {
        uc = getChar();
        
        if (uc == '"') {
            //
            // end of string
            //
            if (range_length > 0) {
                // flush previously captured string fragment
                result.append(dataOffset(range_location), range_length);
                range_length = 0;
            }
            break;
            
        } else if (uc == '\\') {
            //
            // escaped character
            //
            if (range_length > 0) {
                // flush previously captured string fragment
                result.append(dataOffset(range_location), range_length);
                range_length = 0;
            }
            error = parseEscapedCharacter(result);
            if (error) {
                break;
            }
            // Valid escaped character. Keep start for new fragment
            range_location = _offset;
            continue;
            
            
        } else if (uc < 32) {
            setParserError("Unexpected control character in string");
            error = true;
            break;
        }
        
        //
        // valid characted, just increase length in capturing range
        //
        range_length++;
    }
    
    if (range_length > 0) {
        setParserError("Unexpected end of string");
        error = true;
    }
    if (!error) {
        return JsonValue(result.stringView());
    }
    return JsonValue();
}

static bool _Hex2Char(const cc7::byte * p, cc7::byte & out)
{
    int b1, b2;
    if (p[0] >= '0' && p[0] <= '9') {
        b1 = p[0] - '0';
    } else if (p[0] >= 'A' && p[0] <= 'F') {
        b1 = p[0] - 'A' + 10;
    } else if (p[0] >= 'a' && p[0] <= 'f') {
        b1 = p[0] - 'a' + 10;
    } else {
        return false;
    }
    if (p[1] >= '0' && p[1] <= '9') {
        b2 = p[1] - '0';
    } else if (p[1] >= 'A' && p[1] <= 'F') {
        b2 = p[1] - 'A' + 10;
    } else if (p[1] >= 'a' && p[1] <= 'f') {
        b2 = p[1] - 'a' + 10;
    } else {
        return false;
    }
    out = (b1 << 4) | b2;
    return true;
}

static bool _UTF8Encode(cc7::U32 codepoint, ByteArray & out)
{
    cc7::byte buffer[4];
    if(codepoint < 0x80) {
        buffer[0] = (char)codepoint;
        out.append(buffer, 1);
    } else if(codepoint < 0x800) {
        buffer[0] = 0xC0 + ((codepoint & 0x7C0) >> 6);
        buffer[1] = 0x80 + ((codepoint & 0x03F));
        out.append(buffer, 2);
    } else if(codepoint < 0x10000) {
        buffer[0] = 0xE0 + ((codepoint & 0xF000) >> 12);
        buffer[1] = 0x80 + ((codepoint & 0x0FC0) >> 6);
        buffer[2] = 0x80 + ((codepoint & 0x003F));
        out.append(buffer, 3);
// TODO: codepoints greater than 0xFFFF are not possible in this impl.
//      } else if(codepoint <= 0x10FFFF) {
//          buffer[0] = 0xF0 + ((codepoint & 0x1C0000) >> 18);
//          buffer[1] = 0x80 + ((codepoint & 0x03F000) >> 12);
//          buffer[2] = 0x80 + ((codepoint & 0x000FC0) >> 6);
//          buffer[3] = 0x80 + ((codepoint & 0x00003F));
//          out.append(buffer, 4);
    } else {
        return false;
    }
    return true;
}

bool JsonReader::parseEscapedCharacter(ByteArray & result)
{
    static const cc7::byte escaped[5] =
    {
        '\n', '\r', '\t', '\b', '\f'
    };

    //
    // offset points after backslash
    //
    const cc7::byte * ucptr = shouldReadPtr(1);
    if (!ucptr) {
        setParserError("Unexpected end of string");
        return true;
    }
    
    cc7::byte uc_bytes[2];
    
    size_t consumed = 1;
    switch (ucptr[0])
    {
        case '"':
        case '/':
        case '\\':
            // quote, slash or backslash
            result.append(ucptr, 1);
            break;
        case 'n':
            // newline
            result.append(escaped + 0, 1);
            break;
        case 'r':
            // carriage return
            result.append(escaped + 1, 1);
            break;
        case 't':
            // horizontal tab
            result.append(escaped + 2, 1);
            break;
        case 'b':
            // backspace
            result.append(escaped + 3, 1);
            break;
        case 'f':
            // formfeed
            result.append(escaped + 4, 1);
            break;
        case 'u':
            // unicode character
            if (!shouldReadPtr(5)) {
                return true;
            }
            // read 4 hexadecimal numbers
            if (!_Hex2Char(ucptr + 1, uc_bytes[1]) || !_Hex2Char(ucptr + 3, uc_bytes[0])) {
                setParserError("Wrong hexadecimal value in escaped unicode character");
                return true;
            }
            if (!_UTF8Encode((cc7::U32(uc_bytes[1]) << 8) | cc7::U32(uc_bytes[0]), result)) {
                setParserError("Wrong UTF8 codepoint");
                return true;
            }
            consumed = 5;
            break;
            
        default:
            setParserError("Wrong escaped character in string");
            return true;
    }
    // success
    skipCount(consumed);
    return false;
}


//
// Parse number
//

JsonValue JsonReader::parseNumber()
{
    size_t begin = _offset - 1;
    
    bool has_exponent = false;
    bool has_decimal_mark = false;
    bool error = false;
    
    while (!isEnd() && !error)
    {
        cc7::byte uc = getChar();
        if (uc >= '0' && uc <= '9') {
            // regular digit
            continue;
        } else if (uc == '.') {
            // decimal mark
            if (!has_decimal_mark) {
                has_decimal_mark = true;
            } else {
                // double decimal mark
                error = true;
            }
        } else  if (uc == 'e' || uc == 'E') {
            // exponent
            if (!has_exponent && shouldReadPtr(1)) {
                // validate if E is foolowed by +/- or digit
                has_exponent = true;
                uc = getChar();
                if ((uc >= '0' && uc <= '9') || uc == '+' || uc == '-') {
                    continue;
                }
                error = true;
            } else {
                // double exponent symbol or unexpected end
                error = true;
            }
        } else {
            // unknown character, may be processed later
            // we have to go back with offset
            skipBackCount(1);
            break;
        }
    }
    if (!error) {
        try {
            std::string number(charPtr(+ begin), _offset - begin);
            if (has_exponent || has_decimal_mark) {
                return JsonValue(std::stod(number));
            } else {
                return JsonValue((int64_t)std::stoll(number));
            }
        } catch (std::exception & exc) {
            error = true;
        }
    }
    // Set pointer back, at the beginning of the number
    _offset = begin;
    setParserError("Invalid number");
    return JsonValue();
}



// MARK: Public interface

JsonReader::JsonReader()
{
    resetReader(ByteRange());
}

JsonValue JsonReader::parse(const ByteRange &data)
{
    resetReader(data);
    auto out_value = parseValue(nullptr);
    if (out_value.isValid() && _error.empty()) {
        // valid result
        return out_value;
    }
    if (_error.empty() & out_value.isType(JsonValue::NaT)) {
        // empty result, no error
        out_value.assignNull();
        return out_value;
    }
    // regular error
    throw JsonException(_error);
}

JsonValue JsonReader::parse(const std::string_view& string)
{
    return parse(MakeRange(string));
}

JsonValue JsonReader::fromJsonData(const ByteRange& data)
{
    return JsonReader().parse(data);
}

JsonValue JsonReader::fromJsonString(const std::string_view& string)
{
    return JsonReader().parse(string);
}

const std::string& JsonReader::getErrorMessage() const
{
    return _error;
}

} // namespace cc7::json
