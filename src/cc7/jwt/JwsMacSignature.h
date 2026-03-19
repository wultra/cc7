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

#include "JwsBaseAlgorithm.h"
#include <cc7/crypto/MAC.h>

namespace cc7::jwt {

class JwsMacSignature : public JwsBaseAlgorithm
{
public:
    JwsMacSignature(const crypto::MACPtr& mac, const JwsSpec * spec);
    
    ByteArray sign(const JwsKey &key, const ByteRange &data) const override;
    bool verify(const JwsKey &key, const ByteRange &data, const ByteRange &signature) const override;

private:
    const crypto::MACPtr _mac;
    const crypto::ParameterList _mac_params;
    
    static crypto::ParameterList buildParamsForSpec(const JwsSpec* spec);
};

} // namespace cc7::jwt
