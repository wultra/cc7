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

#pragma once

#include <cc7/Platform.h>

namespace cc7::debug {

/**
 Defines assertion handler function. You can override behavior of the assertion handler
 in DEBUG builds of the CC7 library and register your own handler.
 The handler will be notified about all failures, produced by CC7_ASSERT() macro.
 */
typedef void (*AssertionHandler)(void * handler_data, const char * file, int line, const char * formatted_string);

/**
 The AssertionHandlerSetup structure contains pointer to assertion handler and custom data
 for the handler.
 */
struct AssertionHandlerSetup
{
    AssertionHandler    handler;
    void *              handler_data;
};

/**
 Defines a handler for messages produced by CC7_LOG() in all build configurations.
 Logging is enabled by default. The handler runs synchronously on the logging thread
 and may be called concurrently. The formatted string is valid only during the call.
 */
typedef void (*LogHandler)(void * handler_data, const char * formatted_string);

/**
 The LogHandlerSetup structure contains pointer to log handler and custom data
 for the handler.
 */
struct LogHandlerSetup
{
    LogHandler  handler;
    void *      handler_data;
};


/**
 Returns true if the library was compiled with a debug features turned on.
 It is highly recommended to NOT use this kind of build in the production environment.
 */
bool HasDebugFeaturesTurnedOn();

#if defined(ENABLE_CC7_ASSERT)

/**
 Sets a new setup to internal assertion handler. This function is available only
 when CC7_ASSERT() macro is enabled and functional.
 
 Note that the function is not thread-safe. It is recommended to use this feature
 only during the unit testing.
 */
void SetAssertionHandler(const AssertionHandlerSetup & new_setup);

/**
 Returns current assertion handler's setup.
 
 Note that the function is not thread-safe. It is recommended to use this feature
 only during the unit testing.
 */
AssertionHandlerSetup GetAssertionHandler();

/**
 Returns default assertion handler's setup.
 Note that each platform supported by CC7 has its own implementation of this function.
 */
AssertionHandlerSetup Platform_GetDefaultAssertionHandler();

#endif // defined(ENABLE_CC7_ASSERT)

    
#if defined(ENABLE_CC7_LOG)
    
/**
 Sets the internal log handler. A null handler restores the platform default.
 This function is thread-safe. Calls already in progress may still use the previous
 handler, so its handler_data must remain valid until those calls finish.
 */
void SetLogHandler(const LogHandlerSetup & new_setup);

/**
 Returns a thread-safe snapshot of the current log handler's setup.
 */
LogHandlerSetup GetLogHandler();

/**
 Returns default log handler's setup.
 Note that each platform supported by CC7 has its own implementation of this function.
 */
LogHandlerSetup Platform_GetDefaultLogHandler();

/**
 Sets CC7 logging enabled or disabled. This function is thread-safe.
 */
void SetLogEnabled(bool enabled);

/**
 Returns true if CC7 logging is enabled. This function is thread-safe.
 */
bool IsLogEnabled();

/**
 Returns default enabled state for cc7 logging.
 Note that each platform supported by CC7 has its own implementation of this function.
 */
bool Platform_IsDefaultLogEnabled();

#endif // defined(ENABLE_CC7_LOG)

} // namespace cc7::debug
