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

#include <cc7/detail/StringUtils.h>
#include <sstream>
#include <memory>
#include <stdlib.h>

namespace cc7 {
namespace detail {

std::string FormattedString(const char * format, ...)
{
    va_list ap;
    va_start(ap, format);
    int expected_size = vsnprintf(NULL, 0, format, ap);
    va_end(ap);
    if (expected_size < 0) {
        throw std::logic_error("vsnprintf() encoding error occured: " + std::to_string(expected_size));
    }
    std::unique_ptr<char[]> buffer;
    buffer.reset(new char[expected_size + 1]);
    va_start(ap, format);
    int processed_size = vsnprintf(&buffer[0], expected_size + 1, format, ap);
    va_end(ap);
    if (expected_size != processed_size) {
        // TODO: assertion would be better?
        throw std::logic_error("vsnprintf() different exp. and processed size: " + std::to_string(expected_size) + " vs " + std::to_string(processed_size));
    }
    return std::string(buffer.get());
}


std::vector<std::string> & SplitString(const std::string & str, char delim, std::vector<std::string> & elems, bool skip_empty)
{
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!skip_empty || !item.empty()) {
            elems.push_back(item);
        }
    }
    return elems;
}


std::vector<std::string> SplitString(const std::string & str, char delimiter, bool skip_empty)
{
    std::vector<std::string> elements;
    SplitString(str, delimiter, elements, skip_empty);
    return elements;
}


} // namespace detail
} // namespace cc7
