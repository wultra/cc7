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

#include <cc7/json/JsonValue.h>
#include <cc7/json/JsonException.h>

namespace cc7 {
namespace json {

class JsonReader
{
public:
    
    JsonReader();
    
    JsonValue parse(const ByteRange& data);
    JsonValue parse(const std::string_view& string);
    
    const std::string& getErrorMessage() const;
    
    static JsonValue fromJsonData(const ByteRange& data);
    static JsonValue fromJsonString(const std::string_view& string);
        
private:
    
    void setParserError(const char * reason);
    
    // Stream reading
    void resetReader(const ByteRange& range);
    
    bool isEnd();
    const cc7::byte * dataPtr();
    const cc7::byte * dataOffset(size_t offset);
    const char * charPtr(size_t offset);
    cc7::byte getChar();
    const cc7::byte * shouldReadPtr(size_t requiredSize);
    void skipCount(size_t count);
    void skipBackCount(size_t count);
    cc7::byte skipWhitespace();
    
    // Stack
    bool pushStack();
    bool popStack();
    
    // Parser
    JsonValue parseValue(const cc7::byte * allowedSeparators);
    JsonValue parseArray();
    JsonValue parseObject();
    JsonValue parseString();
    bool parseEscapedCharacter(ByteArray & result);
    JsonValue parseNumber();
    
    // Private Members
    
    const cc7::byte * _ptr;
    
    size_t  _offset;
    size_t  _length;
    size_t  _line;
    size_t  _lineBegin;
    
    int     _stack;
    int     _stackLimit;
    int     _options;
    
    bool        _unexpectedEndOfStream;
    cc7::byte   _consumedSeparator;
    
    std::string _error;
};

} // namespace json
} // namespace cc7
