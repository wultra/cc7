/*
 * Copyright 2016 Juraj Durech <durech.juraj@gmail.com>
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

#include <cc7/DebugFeatures.h>
#include <atomic>
#include <mutex>

namespace cc7 {
namespace debug {
    
#if defined(DEBUG) || defined(ENABLE_CC7_LOG) || defined(ENABLE_CC7_ASSERT)
// Following string is useful for debug build detection during the library deployment.
// You can check whether final executable or library doesn't contain this string,
// to be sure that the release build was really produced.
const char * gFooDEBUG = "ThisIsDebugBuild_CC7";
#endif

//
// Must be always implemented. Doesn't depend on assert.
//
bool HasDebugFeaturesTurnedOn()
{
#if defined(DEBUG) || defined(ENABLE_CC7_LOG) || defined(ENABLE_CC7_ASSERT)
    return true;
#else
    return false;
#endif
}
    
    
#if defined(ENABLE_CC7_ASSERT)
//
// Assertion handler
//
static AssertionHandlerSetup s_assert_setup = { nullptr, nullptr };

void SetAssertionHandler(const AssertionHandlerSetup & new_setup)
{
    AssertionHandlerSetup default_setup = Platform_GetDefaultAssertionHandler();
    if (!new_setup.handler) {
        s_assert_setup = default_setup;
    } else {
        s_assert_setup = new_setup;
    }
}

AssertionHandlerSetup GetAssertionHandler()
{
    return s_assert_setup;
}
#endif //ENABLE_CC7_ASSERT


#if defined(ENABLE_CC7_LOG)
//
// Log handler
//
struct LogState
{
    std::mutex mutex;
    LogHandlerSetup setup = { nullptr, nullptr };
    std::atomic<bool> enabled { Platform_IsDefaultLogEnabled() };
};

static LogState& GetLogState()
{
    static LogState state;
    return state;
}

void SetLogHandler(const LogHandlerSetup & new_setup)
{
    auto setup = new_setup.handler ? new_setup : Platform_GetDefaultLogHandler();
    auto& state = GetLogState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.setup = setup;
}

LogHandlerSetup GetLogHandler()
{
    auto& state = GetLogState();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.setup.handler ? state.setup : Platform_GetDefaultLogHandler();
}

void SetLogEnabled(bool enabled)
{
    GetLogState().enabled.store(enabled);
}

bool IsLogEnabled()
{
    return GetLogState().enabled.load();
}
#endif //ENABLE_CC7_LOG


} // cc7::debug
} // cc7


#if defined(ENABLE_CC7_ASSERT)
//
// Real assert implementation, should not be wrapper in any namespace.
//
int CC7AssertImpl(int condition, const char * file, int line, const char * fmt, ...)
{
    if (condition) {
        // assertion did not fail, just return positive value
        return 1;
    }
    
    // Format input string
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, 1024, fmt, args);
    buffer[1024 - 1] = 0;
    va_end(args);
    
    // Look for file name component from "file"
    // Printing just file name component from the path increases readability (IMO)
    const char * separator = strrchr(file, '/');
    if (!separator) {
        separator = strrchr(file, '\\');
    }
    const char * file_name = separator ? separator + 1 : file;
    
    // Build final string
    char message[1024];
    snprintf(message, 1024, "CC7_ASSERT: %s, %d: %s", file_name, line, buffer);
    message[1024 - 1] = 0;
    
    // Pass that message to the assert handler
    if (!cc7::debug::s_assert_setup.handler) {
        cc7::debug::s_assert_setup = cc7::debug::Platform_GetDefaultAssertionHandler();
        if (cc7::debug::s_assert_setup.handler) {
            cc7::debug::s_assert_setup.handler(cc7::debug::s_assert_setup.handler_data, file_name, line, message);
        }
    } else {
        cc7::debug::s_assert_setup.handler(cc7::debug::s_assert_setup.handler_data, file_name, line, message);
    }
    
    // Function must return 0 due to fact, that CC7AssertImpl() is also used in CC7_CHECK() macros.
    return condition;
}
#endif //ENABLE_CC7_ASSERT


#if defined(ENABLE_CC7_LOG)
//
// Real log implementation, should not be wrapper in any namespace.
//
void CC7LogImpl(const char * fmt, ...)
{
    if (!cc7::debug::IsLogEnabled()) {
        return;
    }
    
    const auto setup = cc7::debug::GetLogHandler();
    if (!setup.handler) {
        return;
    }

    char message[1024];
    va_list args;
    va_start(args, fmt);
    const int length = vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (length < 0) {
        setup.handler(setup.handler_data, "CC7: Failed to format log message");
        return;
    }
    if (static_cast<size_t>(length) < sizeof(message)) {
        setup.handler(setup.handler_data, message);
        return;
    }

    std::vector<char> full_message(static_cast<size_t>(length) + 1);
    va_start(args, fmt);
    const int full_length = vsnprintf(full_message.data(), full_message.size(), fmt, args);
    va_end(args);
    if (full_length != length) {
        setup.handler(setup.handler_data, "CC7: Failed to format full log message");
        return;
    }
    setup.handler(setup.handler_data, full_message.data());
}

void CC7LogEnableImpl(bool enable)
{
    cc7::debug::SetLogEnabled(enable);
}
bool CC7LogIsEnabledImpl()
{
    return cc7::debug::IsLogEnabled();
}
#endif //ENABLE_CC7_LOG
