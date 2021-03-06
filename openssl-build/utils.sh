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

###############################################################################

source "${TOP}/common-functions.sh"

# -----------------------------------------------------------------------------
# ACQUIRE_LOCK implements simple exclusive lock by creating a temporary directory
#
# Parameters:
#   $1   - path to lock directory
# -----------------------------------------------------------------------------
function ACQUIRE_LOCK
{   
    set +e
    local lock_dir="$1"
    local lock_wait=$2
    local count=0
    while ! mkdir "${lock_dir}" > /dev/null 2>&1; do
        count=$((count + 1))
        if [ ${count} -eq ${lock_wait} ]; then
            LOG "Unable to acquire exclusive lock for $lock_wait seconds. You can fix this, but you have to:"
            LOG " - Try execute this comand later."
            LOG " - Try execute with '--remove-lock' switch, to force-remove the lock."
            FAILURE "Failed to acquire lock: ${lock_dir}"
        fi
        DEBUG_LOG "Unable to acquire lock. Waiting for 1 second..."
        sleep 1
    done
    set -e
    DEBUG_LOG "Successfully acquired lock: ${lock_dir}"
    
    # Catch possible failures and remove lock in such case.
    trap "REMOVE_LOCK ${lock_dir}" EXIT INT TERM HUP
}

# -----------------------------------------------------------------------------
# REMOVE_LOCK removes lock previously acquired by ACQUIRE_LOCK
#
# Parameters:
#   $1   - path to lock directory
# -----------------------------------------------------------------------------
function REMOVE_LOCK
{
    local lock_dir="$1"
    [[ -d "${lock_dir}" ]] && rmdir "${lock_dir}" && DEBUG_LOG "Successfully removed lock: ${lock_dir}"
    
    # Remove trap handler.
    trap - EXIT INT TERM HUP
}

# -----------------------------------------------------------------------------
# LOAD_ARCHIVE_INFO_FILE loads content of precompiled package info file. 
#
# Parameters:
#   $1   - Path to precompiled package info file.
# -----------------------------------------------------------------------------
function LOAD_ARCHIVE_INFO_FILE
{
    local info_path="$2"
    if [ -f "${info_path}" ]; then
        source "${info_path}"
        if [ -z ${OPENSSL_PREBUILD_VERSION} ] || [ -z ${OPENSSL_PREBUILD_HASH} ]; then
            FAILURE "Package info file has no content: ${info_path}"
        fi
    else
        FAILURE "Missing required package info file: ${info_path}"
    fi
}

# -----------------------------------------------------------------------------
# SAVE_ARCHIVE_INFO_FILE saves "build-info.sh" file into 
#
# Parameters:
#   $1   - path to archive with precompiled, platform specific library.
#   $2   - (optional) hash. If not provided, then hash is calculated from archive.
# -----------------------------------------------------------------------------
function SAVE_ARCHIVE_INFO_FILE
{
    local archive="$1"
    local archive_hash=${2:-$(SHA256 $archive)}
    local info_path=
    case $archive in
        *-apple.tar.gz) info_path="${OPENSSL_DEST_APPLE_INFO}" ;;
        *.xcframework.zip) info_path="${OPENSSL_DEST_APPLE_XCFW_INFO}" ;;
        *-android.tar.gz) info_path="${OPENSSL_DEST_ANDROID_INFO}" ;;
        *) FAILURE "Unable to determine platform from the precompiled archive: $archive" ;;
    esac
    local archive_file=$(basename "$archive")
    DEBUG_LOG "Updating archive info file for archive $archive_file"    
    cat > ${info_path} <<EOF
# ----------------------------------------------    
# Please do not modify this autogenerated file.'
# ----------------------------------------------
OPENSSL_PREBUILD_VERSION='${OPENSSL_VERSION}'   
OPENSSL_PREBUILD_HASH='${archive_hash}'
EOF
}