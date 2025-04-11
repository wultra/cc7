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
#include <cc7/crypto/Constants.h>
#include <cc7/crypto/BaseObject.h>

namespace cc7
{
namespace crypto
{

/// The `Parameter` class
class Parameter
{
public:
    
    static Parameter from(bool value);
    static Parameter from(size_t value);
    static Parameter from(int64_t value);
    static Parameter from(const std::string & str);
    static Parameter from(const ByteRange & range);
    static Parameter from(const BaseObjectPtr & object);
    
    static Parameter copyFrom(const std::string & str);
    static Parameter copyFrom(const ByteRange & range);
    
    bool asBool() const;
    size_t asSize() const;
    int64_t asInt() const;
    const std::string & asString() const;
    const ByteRange & asByteRange() const;
    BaseObjectPtr asObject() const;

private:

    /// Internal parameter's value implementation.
    class Value
    {
    public:
        const std::string & asString() const;
        const cc7::ByteRange & asByteRange() const;
        BaseObjectPtr asObject() const;
        bool asBool() const;
        size_t asSize() const;
        int64_t asInt() const;
        
        Value(bool value);
        Value(size_t value);
        Value(int64_t value);
        
        Value(const std::string & str, bool copy);
        Value(const ByteRange & range, bool copy);
        Value(const BaseObjectPtr & object);
        ~Value();
        
    private:
        
        enum Type {
            T_Bool,
            T_Size,
            T_Int,
            T_String,
            T_StringRef,
            T_Range,
            T_Array,
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
            /// Pointer to allocated base object ptr.
            BaseObjectPtr * _object_ptr;
        };
    };
    
    Parameter(Value * v) : _value(v) {}
    
    const std::shared_ptr<Value>_value;
};

} // cc7::crypto
} // cc7
