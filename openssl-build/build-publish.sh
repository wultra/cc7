#!/bin/bash
###############################################################################

if [ x$OPENSSL_VERSION == 'x' ]; then
	echo "Do not use this script explicitly. Use 'build.sh' instead."
	exit 1
fi

# -----------------------------------------------------------------------------
# PUBLISH_COMMIT_CHANGES displays info about release publishing
# -----------------------------------------------------------------------------
function PUBLISH_COMMIT_CHANGES
{
	local release_url="${CC7_RELEASE_URL}/${CC7_VERSION}"

	LOG "Commiting all chages..."
	
	SAVE_FETCH_CONFIG
	
	LOG_LINE
	LOG "To publish OpenSSL ${OPENSSL_VERSION} for cc7 release ${CC7_VERSION},"
	LOG " you should do the following steps:"
	LOG "    - commit and push all local changes into the git"
	LOG "    - create and push tag ${CC7_VERSION}"
	LOG "    - collect all platform archives:"
	[[ x${DO_ANDROID} == x1 ]] && LOG "        - ${OPENSSL_DEST_ANDROID_PATH}"
	[[ x${DO_APPLE}   == x1 ]] && LOG "        - ${OPENSSL_DEST_APPLE_PATH}"
	LOG "    - upload above archives into assets: $release_url"
}

# -----------------------------------------------------------------------------
# PUBLISH_ARCHIVE saves just created build into config-fetch.sh 
# 
# Parameters:
#   $1   - precompiled archive to publish
# -----------------------------------------------------------------------------
function PUBLISH_ARCHIVE
{
	local archive="$1"
	local info_path=
	local platform=
	local hash=
	local BASE_URL="${CC7_RELEASE_URL}/download"
	
	case "$archive" in
		*-apple.tar.gz) 
			info_path="${OPENSSL_DEST_APPLE_INFO}"
			platform="Apple"
			;;
		*-android.tar.gz)
			info_path="${OPENSSL_DEST_ANDROID_INFO}"
			platform="Android"
			;;
		*) 
			FAILURE "Unable to determine platform from the precompiled archive: $archive"
			;;
	esac
	
	LOG "Publishing OpenSSL ${OPENSSL_VERSION} for ${platform} platform..."
	
	if [ ! -f "${archive}" ]; then
		FAILURE "Missing archive file for ${platform} platform: ${archive}"
	fi

	# Load fetch config & package info file
	
	LOAD_FETCH_CONFIG
	LOAD_ARCHIVE_INFO_FILE required "${info_path}"
	
	hash=${OPENSSL_PREBUILD_HASH}
	if [ $platform == 'Apple' ]; then
		OPENSSL_FETCH_APPLE_URL="${BASE_URL}/${CC7_VERSION}/${OPENSSL_DEST_APPLE_FILE}"
		OPENSSL_FETCH_APPLE_HASH=$hash
	else
		OPENSSL_FETCH_ANDROID_URL="${BASE_URL}/${CC7_VERSION}/${OPENSSL_DEST_ANDROID_FILE}"
		OPENSSL_FETCH_ANDROID_HASH=$hash
	fi

	LOG "  - Precompiled archive : ${archive}"
	LOG "  - Info path           : ${info_path}"
	LOG "  - Hash                : ${hash}"
}

# -----------------------------------------------------------------------------
# LOAD_FETCH_CONFIG loads config-fetch.sh into OPENSSL_FETCH* variables.
# -----------------------------------------------------------------------------
function LOAD_FETCH_CONFIG
{	
	DEBUG_LOG "Loading config-fetch.sh ..."
	
	if [ ! -z $OPENSSL_FETCH_VERSION ] && [ "$OPENSSL_FETCH_VERSION" == "${OPENSSL_VERSION}" ]; then
		DEBUG_LOG "File config-fetch.sh is already loaded."
		return 0
	fi
	
	if [ -f "${TOP}/config-fetch.sh" ]; then
		source "${TOP}/config-fetch.sh"	
		if [ -z $OPENSSL_FETCH_VERSION ] || [ "$OPENSSL_FETCH_VERSION" != "${OPENSSL_VERSION}" ]; then
			DEFAULT_FETCH_CONFIG
		fi
	else
		DEFAULT_FETCH_CONFIG
	fi
}

# -----------------------------------------------------------------------------
# SAVE_FETCH_CONFIG saves OPENSSL_FETCH* variables to config-fetch.sh
# -----------------------------------------------------------------------------
function SAVE_FETCH_CONFIG
{
	DEBUG_LOG "Saving config-fetch.sh ..."
	
	if [ -z $OPENSSL_FETCH_VERSION ] || [ "$OPENSSL_FETCH_VERSION" != "${OPENSSL_VERSION}" ]; then
		DEFAULT_FETCH_CONFIG
	fi
	
	local dst_config="${TOP}/config-fetch.sh"
	local tmp_config="${dst_config}.tmp"
	
	echo '# ------------------------------------------------------- #'	>  ${tmp_config}
	echo '#      Please do not modify this autogenerated file.      #'	>> ${tmp_config}
	echo '#  Use  >> build.sh --publish <<  to update its content.  #'	>> ${tmp_config}
	echo '# ------------------------------------------------------- #'	>> ${tmp_config}
	echo ''																>> ${tmp_config}
	echo "OPENSSL_FETCH_VERSION='${OPENSSL_FETCH_VERSION}'"				>> ${tmp_config}
	echo "OPENSSL_FETCH_ANDROID_URL='${OPENSSL_FETCH_ANDROID_URL}'"		>> ${tmp_config}
	echo "OPENSSL_FETCH_ANDROID_HASH='${OPENSSL_FETCH_ANDROID_HASH}'"	>> ${tmp_config}
	echo "OPENSSL_FETCH_APPLE_URL='${OPENSSL_FETCH_APPLE_URL}'"			>> ${tmp_config}
	echo "OPENSSL_FETCH_APPLE_HASH='${OPENSSL_FETCH_APPLE_HASH}'"		>> ${tmp_config}
	
	$MV "${tmp_config}" "${dst_config}"
}

# -----------------------------------------------------------------------------
# DEFAULT_FETCH_CONFIG sets default values OPENSSL_FETCH* variables.
# -----------------------------------------------------------------------------
function DEFAULT_FETCH_CONFIG
{
	DEBUG_LOG "Setting default values for config-fetch.sh ..."
	
	local BASE_URL="${CC7_RELEASE_URL}/download"
	OPENSSL_FETCH_VERSION="${OPENSSL_VERSION}"
	OPENSSL_FETCH_ANDROID_URL="${BASE_URL}/${CC7_VERSION}/${OPENSSL_DEST_ANDROID_FILE}"
	OPENSSL_FETCH_ANDROID_HASH=''
	OPENSSL_FETCH_APPLE_URL="${BASE_URL}/${CC7_VERSION}/${OPENSSL_DEST_APPLE_FILE}"
	OPENSSL_FETCH_APPLE_HASH=''
}