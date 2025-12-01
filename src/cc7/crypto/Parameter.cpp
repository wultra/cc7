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

#include <cc7/crypto/Parameter.h>
#include "CryptoPrivate.h"
#include <stdexcept>

namespace cc7::crypto {

// MARK: - Parameter implementation

// Value getters

const std::string & Parameter::asString() const
{
    return _value->asString();
}

const ByteRange & Parameter::asByteRange() const
{
    return _value->asByteRange();
}

ByteArray & Parameter::asOutArray() const
{
    return _value->asOutArray();
}

bool Parameter::asBool() const
{
    return _value->asBool();
}

size_t Parameter::asSize() const
{
    return _value->asSize();
}

int64_t Parameter::asInt() const
{
    return _value->asInt();
}

BaseObjectPtr Parameter::asObject() const
{
    return _value->asObject();
}

// Param construction

Parameter Parameter::take(bool value)
{
    return Parameter(new Value(value));
}

Parameter Parameter::take(size_t value)
{
    return Parameter(new Value(value));
}

Parameter Parameter::take(int64_t value)
{
    return Parameter(new Value(value));
}

Parameter Parameter::take(const BaseObjectPtr & object)
{
    return Parameter(new Value(object));
}

Parameter Parameter::ref(const char* str)
{
    return Parameter(new Value(str));
}

Parameter Parameter::ref(const std::string & str)
{
    return Parameter(new Value(str, false));
}

Parameter Parameter::ref(const ByteRange & range)
{
    return Parameter(new Value(range, false));
}

Parameter Parameter::outRef(ByteArray & array)
{
    return Parameter(new Value(array));
}

Parameter Parameter::copy(const char* str)
{
    return Parameter(new Value(str));
}

Parameter Parameter::copy(const std::string & str)
{
    return Parameter(new Value(str, true));
}

Parameter Parameter::copy(const ByteRange & range)
{
    return Parameter(new Value(range, true));
}


// MARK: - Parameter::Value implementation

const std::string & Parameter::Value::asString() const
{
    if (_t == T_String || _t == T_StringRef ) {
        return *_string_ptr;
    }
    throw std::invalid_argument("Parameter must be type of string");
}

const cc7::ByteRange & Parameter::Value::asByteRange() const
{
    if (_t == T_Range || _t == T_Array) {
        return _range;
    }
    throw std::invalid_argument("Parameter must be type of byte range");
}

ByteArray & Parameter::Value::asOutArray() const
{
    if (_t == T_OutArray) {
        return *_out_array_ptr;
    }
    throw std::invalid_argument("Parameter must be type of output array");
}

BaseObjectPtr Parameter::Value::asObject() const
{
    if (_t == T_Object) {
        return *_object_ptr;
    }
    throw std::invalid_argument("Parameter must be type of object pointer");
}

bool Parameter::Value::asBool() const
{
    if (_t == T_Bool) {
        return _bool_value;
    }
    throw std::invalid_argument("Parameter must be type of bool");
}

size_t Parameter::Value::asSize() const
{
    if (_t == T_Size) {
        return _size_value;
    }
    throw std::invalid_argument("Parameter must be type of size_t");
}

int64_t Parameter::Value::asInt() const
{
    if (_t == T_Int) {
        return _int_value;
    }
    throw std::invalid_argument("Parameter must be type of int");
}

// Value construction

Parameter::Value::Value(bool value)    : _t(T_Bool), _bool_value(value) {}
Parameter::Value::Value(size_t value)  : _t(T_Size), _size_value(value) {}
Parameter::Value::Value(int64_t value) : _t(T_Int),  _int_value(value) {}

Parameter::Value::Value(const char* str)
{
    _t = T_String;
    _string_ptr = new std::string(str);
    _range = MakeRange(*_string_ptr);
}

Parameter::Value::Value(const std::string & str, bool copy)
{
    if (copy) {
        _t = T_String;
        _string_ptr = new std::string(str);
    } else {
        _t = T_StringRef;
        _string_ptr = &str;
    }
    _range = MakeRange(*_string_ptr);
}

Parameter::Value::Value(const ByteRange & range, bool copy)
{
    if (copy) {
        _t = T_Array;
        _array_ptr = new ByteArray(range);
        _range = _array_ptr->byteRange();
    } else {
        _t = T_Range;
        _range = range;
    }
}

Parameter::Value::Value(ByteArray & out_array)
{
    _t = T_OutArray;
    _out_array_ptr = &out_array;
}

Parameter::Value::Value(const BaseObjectPtr & ptr)
{
    _t = T_Object;
    _object_ptr = new BaseObjectPtr();
    *_object_ptr = ptr;
}

Parameter::Value::~Value()
{
    switch (_t) {
        case T_String:
            delete _string_ptr;
            break;
        case T_Array:
            delete _array_ptr;
            break;
        case T_Object:
            delete _object_ptr;
            break;
        default:
            break;
    }
    _string_ptr = nullptr;
}

// MARK: - ParameterLlist

ParameterListCtx ParameterList::beginParameterProcessing() const
{
    return ParameterListCtx();
}

void ParameterList::endParameterProcessing(const ParameterListCtx &ctx) const
{
    for (const auto & item : *this) {
        if (ctx.find(item.first) == ctx.end()) {
            throwUnsupportedParam(item.first);
        }
    }
}

void ParameterList::throwUnsupported() const
{
    if (begin() != end()) {
        throwUnsupportedParam(begin()->first);
    }
}

bool ParameterList::getString(int param_id, ParameterListCtx & ctx, std::string & out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value = it->second.asString();
    }
    return result;
}

bool ParameterList::getStringAsBytes(int param_id, ParameterListCtx & ctx, ByteRange & out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value.assign(MakeRange(it->second.asString()));
    }
    return result;
}

bool ParameterList::getInt(int param_id, ParameterListCtx & ctx, int64_t & out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value = it->second.asInt();
    }
    return result;
}

bool ParameterList::getSize(int param_id, ParameterListCtx & ctx, size_t & out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value = it->second.asSize();
    }
    return result;
}

bool ParameterList::getBytes(int param_id, ParameterListCtx & ctx, ByteRange & out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value = it->second.asByteRange();
    }
    return result;
}

bool ParameterList::getOutArray(int param_id, ParameterListCtx & ctx, ByteArray*& out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value = &it->second.asOutArray();
    }
    return result;
}

bool ParameterList::getObject(int param_id, ParameterListCtx & ctx, BaseObjectPtr & out_value) const
{
    parent_class::const_iterator it;
    auto result = consume(param_id, ctx, it);
    if (result) {
        out_value = it->second.asObject();
    }
    return result;
}

bool ParameterList::consumeParam(int param_id, ParameterListCtx & ctx) const
{
    parent_class::const_iterator foo;
    return consume(param_id, ctx, foo);
}

bool ParameterList::consume(int param_id, ParameterListCtx &ctx, parent_class::const_iterator &out) const
{
    out = find(param_id);
    bool found = out != end();
    if (found) {
        ctx.insert(param_id);
    }
    return found;
}

} // namespace cc7::crypto
