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

#include "MLKEM.h"

namespace cc7
{
namespace crypto
{

// MARK: - MLKEMSpec implementation

const MLKEMSpec MLKEMSpec::ML_KEM_512  = { "ML-KEM-512" };
const MLKEMSpec MLKEMSpec::ML_KEM_768  = { "ML-KEM-768" };
const MLKEMSpec MLKEMSpec::ML_KEM_1024 = { "ML-KEM-1024" };

const MLKEMSpec * MLKEMSpec::specForAlgorithm(const std::string & algorithm)
{
    if (algorithm == ML_KEM_512.name) {
        return &ML_KEM_512;
    } else if (algorithm == ML_KEM_768.name) {
        return &ML_KEM_768;
    } else if (algorithm == ML_KEM_1024.name) {
        return &ML_KEM_1024;
    }
    return nullptr;
}


// MARK: - MLKEM implementation

std::shared_ptr<MLKEM> MLKEM::getInstance(const std::string & algorithm)
{
    auto spec = MLKEMSpec::specForAlgorithm(algorithm);
    if (spec == nullptr) {
        return nullptr;
    }
    //return std::shared_ptr<MLKEM>(new MLKEM(spec));
    return nullptr;
}



} // cc7::crypto
} // cc7
