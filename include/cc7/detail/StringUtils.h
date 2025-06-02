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
namespace detail {

/// Returns formatted std::string like regular sprintf() does.
/// - Parameter format: Format specification.
/// - Returns: Formatted string
std::string FormattedString(const char * format, ...);

/// Returns a vector containing substrings from the input string that have been divided by a given delimiter.
/// - Parameters:
///   - str: String to split.
///   - delim: Character delimiter
///   - elems: Output vector where substrings will be stored.
/// - Returns: Reference to provided `elems` vector.
std::vector<std::string> & SplitString(const std::string & str, char delim, std::vector<std::string> & elems, bool skip_empty = true);


/// Returns a vector containing substrings from the input string that have been divided by a given delimiter.
/// - Parameters:
///   - str: String to split
///   - delimiter: Character delimiter
/// - Returns: Vector of strings with each element found in the array.
std::vector<std::string> SplitString(const std::string & str, char delimiter, bool skip_empty = true);

} // namespace detail
} // namespace cc7
