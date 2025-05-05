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

#include "NullKDF.h"

namespace cc7
{
namespace crypto
{

const std::string NullKDF::NULL_KDF = "NULL-KDF";

cc7::ByteArray NullKDF::deriveKeyBytes(const ByteRange & key_material, const ParameterList & parameters) const
{
    size_t out_size = _out_key_size;
    
    auto param_ctx = parameters.beginParameterProcessing();
    parameters.getSize(PARAM_OUT_KEY_SIZE, param_ctx, out_size);
    parameters.consumeParam(PARAM_OUT_KEY_TYPE, param_ctx);
    parameters.endParameterProcessing(param_ctx);
    
    if (!out_size) {
        // No size specified, use size from key material
        return key_material;
    }
    
    if (out_size > key_material.size()) {
        // requested key size is greater than provided key
        throw std::invalid_argument("Requested key size is greater than provided key.");
    }
    ByteArray out = key_material;
    if (out_size != out.size()) {
        out.resize(out_size);
    }
    return out;
}

const std::string & NullKDF::getAlgorithmName() const
{
    return NULL_KDF;
}

void NullKDF::setParameter(int param_id, const Parameter & value)
{
    switch (param_id) {
        case PARAM_OUT_KEY_TYPE:
            _out_key_type = value.asString();
            _out_key_size = SymmetricKey::getInstance(_out_key_type)->getKeySize();
            break;
        case PARAM_OUT_KEY_SIZE:
            _out_key_type = value.asString();
            break;
        default:
            throwUnsupportedParam(param_id);
    }
}

Parameter NullKDF::getParameter(int param_id) const
{
    switch (param_id) {
        case PARAM_OUT_KEY_TYPE:
            return Parameter::from(_out_key_type);
            
        case PARAM_OUT_KEY_SIZE:
            return Parameter::from(_out_key_size);
            
        default:
            throwUnsupportedParam(param_id);
    }
}


} // cc7::crypto
} // cc7
