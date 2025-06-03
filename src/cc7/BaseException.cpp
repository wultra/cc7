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

#include <cc7/BaseException.h>

namespace cc7 {

const std::string CLASS_NAME = "cc7::BaseException";

BaseException::BaseException(const char* message, std::exception_ptr cause) noexcept :
    _message(message ? std::string(message) : CLASS_NAME),
    _cause(std::move(cause))
{
}

BaseException::BaseException(const std::string& message, std::exception_ptr cause) noexcept :
    _message(message.empty() ? CLASS_NAME : message),
    _cause(std::move(cause))
{
}

const std::string & BaseException::exceptionClass() const noexcept
{
    return CLASS_NAME;
}

#ifdef DEBUG
static std::string formatDebugDump(const std::string & indent, const std::string & type, const std::string & msg)
{
    return indent + "[ " + type + " ]: " +  msg;
}

std::string BaseException::debugDump() const noexcept
{
    std::string indent;
    std::string out = formatDebugDump(indent, exceptionClass(), message());
    
    std::exception_ptr inner = _cause, current;
    while (inner != nullptr) {
        out    += "\n";
        indent += "  ";
        std::string type, msg;
        try {
            current = inner;
            inner = nullptr;
            std::rethrow_exception(current);
        } catch (BaseException & chained) {
            type = chained.exceptionClass();
            msg = chained.message();
            inner = chained.cause();
        } catch (std::invalid_argument & e) {
            type = "std::invalid_argument";
            msg = e.what();
        } catch (std::runtime_error & e) {
            type = "std::runtime_error";
            msg = e.what();
        } catch (std::domain_error & e) {
            type = "std::domain_error";
            msg = e.what();
        } catch (std::logic_error & e) {
            type = "std::logic_error";
            msg = e.what();
        } catch (std::exception & e) {
            type = "std::exception";
            msg = e.what();
        } catch (...) {
            type = "unknown";
            msg = "non supported exception type";
        }
        out += formatDebugDump(indent + "+ ", type, msg);
    }
    return out;
}
#else
std::string BaseException::debugDump() const noexcept
{
    // In non-DEBUG build return message
    return _message;
}
#endif // DEBUG

} // cc7
