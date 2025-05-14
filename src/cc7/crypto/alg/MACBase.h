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

#include <cc7/crypto/MAC.h>
#include "../CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

struct MACBaseSpec
{
    /// Algorithm name
    std::string  name;
    /// (optional) Message digest name
    std::string  md_name;
    /// Default size of computed mac in bytes
    size_t       mac_size;
    /// Truncate mode. If ON, then MACCommon supports MAC up to mac_size and crop computed MAC to
    /// desired size. If OFF, then algorithm supports variable size out of the box.
    bool         truncate_mode;
};

class MACBase : public MAC
{
public:
    // MAC interface
    ByteArray token(const ByteRange & key, const ByteRange & data, const ParameterList & parameters) const override;
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const Parameter & value) override;
    Parameter getParameter(int param_id) const override;
    
protected:
    
    struct MACBaseParams
    {
        const ParameterList * input;
        ParameterListCtx ctx;
        OSSLParamBuilder builder;
        
        size_t out_len;
    };
    
    virtual bool prepareParams(MACBaseParams & params) const;
    size_t validateMacSize(size_t in_size) const;
    
    EVPMac   _mac;
    size_t  _out_len;
    const MACBaseSpec * _spec;
    
    MACBase(EVPMac & mac, const MACBaseSpec * spec) :
        _mac(mac),
        _out_len(spec->mac_size),
        _spec(spec)
    {
    }
};

} // cc7::crypto
} // cc7
