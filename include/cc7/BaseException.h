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

#include <cc7/Platform.h>

namespace cc7 {

class BaseException : public std::exception
{
public:
    BaseException(const char* message, std::exception_ptr cause = nullptr) noexcept;
    BaseException(const std::string& message, std::exception_ptr cause = nullptr) noexcept;
    
    const std::string & message() const noexcept
    {
        return _message;
    }
    
    const std::exception_ptr & cause() const noexcept
    {
        return _cause;
    }
    
    virtual const std::string& exceptionClass() const noexcept;
    
    std::string debugDump() const noexcept;
    
private:
    std::string _message;
    std::exception_ptr _cause;
};

} // cc7
