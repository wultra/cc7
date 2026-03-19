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

#include "MACBase.h"

namespace cc7::crypto {

class KMAC : public MACBase
{
public:

    static std::shared_ptr<KMAC> getInstance(const std::string & algorithm);
    
public:
    // Algorithm interface
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;

protected:
    
    // OSSLMAC interface
    bool prepareParams(MACBase::MACBaseParams & params) const override;
    
private:
    ByteArray _custom;
    
    KMAC(EVPMac & mac, const MACBaseSpec * spec) : MACBase(mac, spec) {}
};

} // namespace cc7::crypto
