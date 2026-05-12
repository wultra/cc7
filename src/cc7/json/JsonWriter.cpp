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

#include <cc7/json/JsonWriter.h>
#include <cc7/json/JsonException.h>
#include <cc7/detail/StringUtils.h>
#include <cmath>

namespace cc7::json {

// Constants

static const ByteRange cTRUE  = MakeRange("true");
static const ByteRange cFALSE = MakeRange("false");
static const ByteRange cNULL  = MakeRange("null");

static const ByteRange cESC_BSP  = MakeRange("\\b");
static const ByteRange cESC_FF   = MakeRange("\\f");
static const ByteRange cESC_LF   = MakeRange("\\n");
static const ByteRange cESC_CR   = MakeRange("\\r");
static const ByteRange cESC_TAB  = MakeRange("\\t");

static const ByteRange cESC_QUOTATION       = MakeRange("\\\"");
static const ByteRange cESC_SOLIDUS         = MakeRange("\\/");
static const ByteRange cESC_REVERSE_SOLIDUS = MakeRange("\\\\");


// Constructor

JsonWriter::JsonWriter(int options) : _conf(buildConfig((Options)options))
{
}

JsonWriter::Config JsonWriter::buildConfig(Options options)
{
    Config c;
    c.pretty       = (options & PrettyOutput) != 0;
    c.keepNull     = (options & KeepNull) != 0;
    c.escapeSlash  = (options & EscapeSlash) != 0;
    c.doubleFormat = (options & NiceDouble) ? "%.17g" : "%.17e";
    c.maxStack = 16;
    if (c.pretty) {
        c.indentation = MakeRange("  ");
        c.newLine =  MakeRange("\n");
        c.space = MakeRange(" ");
    }
    return c;
}

std::string JsonWriter::toString(const JsonValue &root)
{
    resetWriter();
    writeValue(root);
    return CopyToString(_out);
}

const ByteArray& JsonWriter::toData(const JsonValue &root)
{
    resetWriter();
    writeValue(root);
    return _out;
}

const ByteArray& JsonWriter::getOutputData() const
{
    return _out;
}

std::string JsonWriter::toJsonString(const JsonValue &root, int options)
{
    return JsonWriter(options).toString(root);
}

ByteArray JsonWriter::toJsonData(const JsonValue &root, int options)
{
    return JsonWriter(options).toData(root);
}

// Reset & pretty output helpers

void JsonWriter::resetWriter()
{
    _stack = 0;
    _line_start = 0;
    _indentation.clear();
    _out.clear();
}

void JsonWriter::beginBlock(byte begin_char)
{
    if (++_stack > _conf.maxStack) {
        throw JsonException("The processing stack is too deep");
    }
    _out.append(begin_char);
    if (_conf.pretty) {
        _indentation.append(_conf.indentation);
        newline();
    }
}

void JsonWriter::endBlock(byte end_char)
{
    if (--_stack < 0) {
        throw JsonException("The processing stack is too deep");
    }
    if (_conf.pretty) {
        _indentation.resize(_indentation.size() - _conf.indentation.size());
        newline();
        _out.append(_indentation);
    }
    _out.append(end_char);
}

void JsonWriter::newline()
{
    if (_conf.pretty) {
        if (_line_start != _out.size()) {
            _out.append(_conf.newLine);
            _line_start = _out.size();
        }
    }
}

void JsonWriter::spacer(byte separator)
{
    if (_conf.pretty) {
        _out.append(_conf.space);
    }
    if (separator) {
        _out.append(separator);
        if (_conf.pretty) {
            _out.append(_conf.space);
        }
    }
}

void JsonWriter::nextItem(bool& need_separator)
{
    if (need_separator) {
        _out.append(',');
    } else {
        need_separator = true;
    }
    if (_conf.pretty) {
        newline();
        _out.append(_indentation);
    }
}

void JsonWriter::writeValue(const JsonValue& value)
{
    switch (value.type()) {
        case JsonValue::String:
            writeString(value.asString());
            break;
        case JsonValue::Object:
            writeObject(value.asObject());
            break;
        case JsonValue::Array:
            writeArray(value.asArray());
            break;
        case JsonValue::Boolean:
            _out.append(value.asBoolean() ? cTRUE : cFALSE);
            break;
        case JsonValue::Integer:
            writeInteger(value.asInteger());
            break;
        case JsonValue::Double:
            writeDouble(value.asDouble());
            break;
        case JsonValue::NaT:
            // fallthrough
        case JsonValue::Null:
            _out.append(cNULL);
            break;
            
        default:
            throw std::logic_error("Unsupported JsonValue type enumeration");
    }
}

void JsonWriter::writeString(const JsonValue::TString& string)
{
    _out.append('"');
    cc7::ByteArray translated;
    std::string str;
    for (auto c : string) {
        if ((byte)c < 32) {
            switch (c) {
                case '\b': _out.append(cESC_BSP); break;
                case '\f': _out.append(cESC_FF); break;
                case '\n': _out.append(cESC_LF); break;
                case '\r': _out.append(cESC_CR); break;
                case '\t': _out.append(cESC_TAB); break;
                default: writeHex16(c); break;
            }
        } else if (c == '"') {
            _out.append(cESC_QUOTATION);
        } else if (c == '\\') {
            _out.append(cESC_REVERSE_SOLIDUS);
        } else if (c == '/') {
            if (_conf.escapeSlash) {
                _out.append(cESC_SOLIDUS);
            } else {
                // Escape slash as-is
                _out.append((cc7::byte)c);
            }
        } else {
            _out.append((cc7::byte)c);
        }
    }
    _out.append('"');
}

inline static char IntToHex4(int n)
{
    int nib = n & 0xF;
    return nib < 10 ? '0' + nib : 'a' - 10 + nib;
}

void JsonWriter::writeHex16(int hex)
{
    _tmp.resize(6, ' ');
    auto ptr = _tmp.data();
    ptr[0] = '\\';
    ptr[1] = 'u';
    ptr[2] = IntToHex4(hex >> 12);
    ptr[3] = IntToHex4(hex >> 8);
    ptr[4] = IntToHex4(hex >> 4);
    ptr[5] = IntToHex4(hex);
    _out.append(_tmp);
}

void JsonWriter::writeObject(const JsonValue::TObject& object)
{
    beginBlock('{');
    bool need_separator = false;
    for (const auto& item : object) {
        if (item.first.empty()) {
            throw JsonException("Key is empty string");
        }
        if (item.second.isType(JsonValue::Null) || item.second.isType(JsonValue::NaT)) {
            if (!_conf.keepNull) {
                continue;
            }
        }
        nextItem(need_separator);
        writeString(item.first);
        spacer(':');
        writeValue(item.second);
    }
    endBlock('}');
}

void JsonWriter::writeArray(const JsonValue::TArray& array)
{
    beginBlock('[');
    bool need_separator = false;
    for (const auto& item : array) {
        nextItem(need_separator);
        writeValue(item);
    }
    endBlock(']');
}

void JsonWriter::writeInteger(int64_t value)
{
    auto string = std::to_string(value);
    _out.append(MakeRange(string));
}

void JsonWriter::writeDouble(double value)
{
    if (!std::isfinite(value)) {
        throw JsonException("Floating point value is not a real number");
    }
    auto string = detail::FormattedString(_conf.doubleFormat, value);
    _out.append(MakeRange(string));
}

// MARK: - JsonValue debug

void JsonValue::debugDump() const
{
    JsonWriter writer(JsonWriter::HumanReadable | JsonWriter::KeepNull);
    printf("%s\n", writer.toString(*this).c_str());
}

} // namespace cc7::json
