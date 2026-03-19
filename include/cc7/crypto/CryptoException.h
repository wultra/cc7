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

#include <cc7/BaseException.h>

namespace cc7::crypto {

class CryptoException : public BaseException
{
public:
    using BaseException::BaseException;

    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }

private:
    static const std::string CLASS_NAME;
};


class UnsupportedAlgorithm : public CryptoException
{
public:
    using CryptoException::CryptoException;
    
    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }
    
private:
    static const std::string CLASS_NAME;
};


class InternalError : public CryptoException
{
public:
    using CryptoException::CryptoException;
    
    const std::string & exceptionClass() const noexcept override { return CLASS_NAME; }
    
private:
    static const std::string CLASS_NAME;
};

} // namespace cc7::crypto
