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

#include <cc7/ByteArray.h>
#include <cc7/crypto/CryptoConstants.h>
#include <cc7/crypto/BaseObject.h>
#include <map>
#include <set>

namespace cc7 {
namespace crypto {

/// The `Parameter` class
class Parameter
{
public:
    
    Parameter() = default;
    Parameter(const Parameter&) = default;
    Parameter(Parameter&&) = default;
    Parameter& operator=(const Parameter&) = default;
    Parameter& operator=(Parameter&&) = default;
    ~Parameter() = default;
    
    static Parameter take(bool value);
    static Parameter take(size_t value);
    static Parameter take(int64_t value);
    static Parameter take(const BaseObjectPtr & object);
    static Parameter ref(const std::string & str);
    static Parameter ref(const ByteRange & range);
    static Parameter outRef(ByteArray & array);
    
    static Parameter copy(const std::string & str);
    static Parameter copy(const ByteRange & range);
    
    bool asBool() const;
    size_t asSize() const;
    int64_t asInt() const;
    const std::string & asString() const;
    const ByteRange & asByteRange() const;
    ByteArray & asOutArray() const;
    BaseObjectPtr asObject() const;

private:

    /// Internal parameter's value implementation.
    class Value
    {
    public:
        const std::string & asString() const;
        const cc7::ByteRange & asByteRange() const;
        ByteArray & asOutArray() const;
        BaseObjectPtr asObject() const;
        bool asBool() const;
        size_t asSize() const;
        int64_t asInt() const;
        
        Value(bool value);
        Value(size_t value);
        Value(int64_t value);
        
        Value(const std::string & str, bool copy);
        Value(const ByteRange & range, bool copy);
        Value(ByteArray & out_array);
        Value(const BaseObjectPtr & object);
        ~Value();
        
    private:
        
        friend class ParameterList;
        
        enum Type {
            T_Bool,
            T_Size,
            T_Int,
            T_String,
            T_StringRef,
            T_Range,
            T_Array,
            T_OutArray,
            T_Object
        };

        /// Type of value
        Type _t;
        /// Contains copy of provided input range, or always captures bytes stored in _array_ptr or _string_ptr
        cc7::ByteRange _range;
        
        union {
            /// Simple bool value.
            bool _bool_value;
            /// Simple size value.
            size_t _size_value;
            /// Simple int value.
            int64_t _int_value;
            /// Pointer to allocated or external string.
            const std::string * _string_ptr;
            /// Pointer to allocated byte array.
            const cc7::ByteArray * _array_ptr;
            /// Pointer to output array.
            cc7::ByteArray * _out_array_ptr;
            /// Pointer to allocated base object ptr.
            BaseObjectPtr * _object_ptr;
        };
    };
    
    Parameter(Value * v) : _value(v) {}
    
    std::shared_ptr<Value> _value;
};


typedef std::set<int> ParameterListCtx;

class ParameterList : public std::map<int, Parameter>
{
public:
    typedef std::map<int, Parameter> parent_class;
    
    using parent_class::parent_class;
    using parent_class::insert;

    ParameterList() {}
    
    ParameterListCtx beginParameterProcessing() const;
    void endParameterProcessing(const ParameterListCtx & ctx) const;
    void throwUnsupported() const;
    
    bool getString(int param_id, ParameterListCtx & ctx, std::string & out_value) const;
    bool getStringAsBytes(int param_id, ParameterListCtx & ctx, ByteRange & out_value) const;
    bool getInt(int param_id, ParameterListCtx & ctx, int64_t & out_value) const;
    bool getSize(int param_id, ParameterListCtx & ctx, size_t & out_value) const;
    bool getBytes(int param_id, ParameterListCtx & ctx, ByteRange & out_value) const;
    bool getObject(int param_id, ParameterListCtx & ctx, BaseObjectPtr & out_value) const;
    bool getOutArray(int param_id, ParameterListCtx & ctx, ByteArray*& out_value) const;
    bool consumeParam(int param_id, ParameterListCtx & ctx) const;
    
private:
    
    bool consume(int param_id, ParameterListCtx & info, parent_class::const_iterator & out) const;
};

} // cc7::crypto
} // cc7
