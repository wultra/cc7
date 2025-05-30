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

class JsonWriter
{
public:
    enum Options {
        Default       = 0,
        /// If used, then generated JSON is pretty formatted.
        PrettyOutput  = 1 << 0,
        /// If used, then object properties with `null` value will be serialized.
        /// By default, `null` such properties are omitted and not included to output.
        KeepNull      = 1 << 1,
        /// If used, then also slash (`/`) character in string will be escaped.
        /// By default, slash is not escaped and increases the data readability.
        EscapeSlash   = 1 << 2,
        /// If used, then double type is converted with general double formatter.
        /// This may produce more human readable output, but may lost information that it's double type.
        /// For example, 1000.0 will be exported as 1000 and re-imported as integer.
        NiceDouble    = 1 << 3,
        /// Is used, then produced output is human readable.
        HumanReadable = PrettyOutput | NiceDouble
    };
    
    JsonWriter(int options = Default);
    
    std::string toString(const JsonValue & root);
    const ByteArray& toData(const JsonValue & root);
    
    const ByteArray& getOutputData() const;
    
    static std::string toJsonString(const JsonValue& root, Options options = Default);
    static ByteArray toJsonData(const JsonValue & root, Options options = Default);
    
private:
    struct Config
    {
        bool pretty;
        bool keepNull;
        bool escapeSlash;
        int maxStack;
        ByteRange indentation;
        ByteRange newLine;
        ByteRange space;
        const char * doubleFormat;
    };
        
    static Config buildConfig(Options options);
    
    const Config _conf;
    
    int _stack;
    size_t _line_start;
    
    ByteArray _indentation;
    ByteArray _out;
    ByteArray _tmp;
    
    void resetWriter();
    
    void writeValue(const JsonValue& value);
    void writeString(const JsonValue::TString& string);
    void writeObject(const JsonValue::TObject& object);
    void writeArray(const JsonValue::TArray& array);
    void writeInteger(int64_t value);
    void writeDouble(double value);
    void writeHex16(int hex);
    
    
    void beginBlock(byte begin_char);
    void endBlock(byte end_char);
    void newline();
    void spacer(byte separator);
    void nextItem(bool& need_separator);
};

} // namespace json
} // namespace cc7
