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

#include <cc7/crypto/Key.h>
#include <cc7/Base64.h>
#include "CryptoPrivate.h"

namespace cc7::crypto {

// MARK: - Key

std::string Key::exportKeyToBase64(KeyFormat format) const
{
    return exportKey(format).base64();
}

ByteArray Key::secureExportKeyToBase64(KeyFormat format) const
{
    return Base64::secureEncode(exportKey(format));
}

void Key::importKeyFromBase64(const std::string_view & base64Key, KeyFormat format)
{
    importKey(Base64::decode(base64Key), format);
}

} // namespace cc7::crypto
