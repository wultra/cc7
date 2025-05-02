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

#include <cc7/crypto/KeyDerivation.h>
#include "CryptoPrivate.h"

namespace cc7
{
namespace crypto
{

// MARK: - NullKDF implementation

class NullKDF : public KeyDerivation
{
public:
    // KeyDerivation interface
    virtual cc7::ByteArray deriveKey(const ByteRange & key_material, size_t out_key_size = 0) const
    {
        size_t out_size;
        if (out_key_size) {
            out_size = out_key_size;
        } else if (_out_key_size) {
            out_size = out_key_size;
        } else {
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
    
    // Algorithm interface
    
    virtual const std::string & getAlgorithmName() const
    {
        return NULL_KDF;
    }
    
    virtual void setParameter(int param_id, const Parameter & value)
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
    
    virtual Parameter getParameter(int param_id) const
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
    
    static const std::string NULL_KDF;
    
    NullKDF() : _out_key_size(0) {}
    
private:
    std::string _out_key_type;
    size_t      _out_key_size;
};

const std::string NullKDF::NULL_KDF = "NULL-KDF";



// MARK: - KeyDerivation implementation

std::shared_ptr<KeyDerivation> KeyDerivation::getInstance(const std::string & algorithm)
{
    KeyDerivationPtr kdf;
    if (algorithm == NullKDF::NULL_KDF) {
        kdf = nullDerivation();
    }
    if (kdf == nullptr) {
        throwUnsupporterAlgorithm(algorithm);
    }
    return kdf;
}

std::shared_ptr<KeyDerivation> KeyDerivation::nullDerivation()
{
    return std::shared_ptr<KeyDerivation>(new NullKDF());
}

} // cc7::crypto
} // cc7
