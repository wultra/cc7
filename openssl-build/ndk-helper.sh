#!/bin/bash
# -----------------------------------------------------------------------------
# Copyright 2020 Wultra s.r.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# BUILD_ANDROID_LOOK_FOR_NDK search for NDK in various environment variables
# and set such path into ANDROID_BUILD_NDK_HOME global variable.
# Following variables are evaluated:
#  - ANDROID_NDK_HOME
#  - ANDROID_NDK
#  - NDK_HOME
#  - NDK_ROOT
#  - ANDROID_HOME/ndk-bundle
#  - ANDROID_SDK/ndk-bundle
# -----------------------------------------------------------------------------
function BUILD_ANDROID_LOOK_FOR_NDK
{
    local sdk_path=
    local ndk_source=
    if [ ! -z "${ANDROID_BUILD_NDK_HOME}" ]; then
        return  # already set to global var
    elif [ ! -z "${ANDROID_NDK_USER_HOME}" ]; then
        ANDROID_BUILD_NDK_HOME="${ANDROID_NDK_USER_HOME}"
        ndk_source='ANDROID_NDK_USER_HOME'
    elif [ ! -z "${ANDROID_NDK_HOME}" ]; then
        ANDROID_BUILD_NDK_HOME="${ANDROID_NDK_HOME}"
        ndk_source='ANDROID_NDK_HOME'
    elif [ ! -z "${ANDROID_NDK}" ]; then
        ANDROID_BUILD_NDK_HOME="${ANDROID_NDK}"
        ndk_source='ANDROID_NDK'
    elif [ ! -z "${NDK_HOME}" ]; then
        ANDROID_BUILD_NDK_HOME="${NDK_HOME}"
        ndk_source='NDK_HOME'
    elif [ ! -z "${NDK_ROOT}" ]; then
        ANDROID_BUILD_NDK_HOME="${NDK_ROOT}"
        ndk_source='NDK_ROOT'
    elif [ ! -z "${ANDROID_HOME}" ]; then
        sdk_path="${ANDROID_HOME}"
        ndk_source='ANDROID_HOME'
    elif [ ! -z "${ANDROID_SDK}" ]; then
        sdk_path="${ANDROID_SDK}"
        ndk_source='ANDROID_SDK'
    else
        FAILURE "Unable to determine location of Android NDK."
    fi
    if [ ! -z "$sdk_path" ]; then
        if [ -d "$sdk_path/ndk-bundle" ]; then
            ANDROID_BUILD_NDK_HOME="$sdk_path/ndk-bundle"
            ndk_source+='/ndk-bundle'
        else
            FAILURE "Unable to determine location of Android NDK from SDK folder."
        fi
    fi
    [[ ! -d "${ANDROID_BUILD_NDK_HOME}" ]] && FAILURE "Android NDK located via variable \$${ndk_source}, but directory doesn't exist: ${ANDROID_BUILD_NDK_HOME}"
    DEBUG_LOG "Android NDK located via variable \$${ndk_source} at path: ${ANDROID_BUILD_NDK_HOME}"
}
