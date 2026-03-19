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

#include <cc7tests/CC7Tests.h>
#include <cc7/crypto/Crypto.h>
#include <cc7/Base64.h>
#include <cc7tests/TestDirectory.h>
#include <set>

namespace cc7
{
namespace tests
{
extern TestDirectory g_testFiles;

class NonceGeneratorTests : public UnitTest
{
public:
    NonceGeneratorTests()
    {
        CC7_REGISTER_TEST_METHOD(testDefaultNonceGenerator);
        CC7_REGISTER_TEST_METHOD(testDefaultNonceGeneratorUniqueness);
        CC7_REGISTER_TEST_METHOD(testCollisionResistantNonceGenerator);
        CC7_REGISTER_TEST_METHOD(testSimpleNonceGenerator);
    }
    
    void testDefaultNonceGenerator()
    {
        for (size_t len = 1; len <= 4; len++) {
            const auto nonce_size = len * 16;
            auto generator = crypto::DefaultNonceGenerator::getInstance(nonce_size);
            auto nonces = std::set<ByteArray>();
            for (int i = 0; i < 1000; i++) {
                auto nonce = generator->getNonce();
                //printf("%03d: %s\n", i, nonce.hexString().c_str());
                ccstAssertEqual(nonce_size, nonce.size());
                if (nonces.find(nonce) != nonces.end()) {
                    ccstFailure("Failed at iteration %d, size %d : %s", i, (int)nonce_size, nonce.hexString().c_str());
                }
                nonces.insert(nonce);
            }
            for (auto nonce : nonces) {
                ccstAssertFalse(generator->checkUniqueness(nonce, false));
            }
            // Save state
            auto saved_state = generator->saveState();
            //printf("state: %s\n", saved_state.hexString().c_str());
            ccstAssertTrue(saved_state.size() >= nonce_size * 1000);
            // Not modified after save
            for (auto nonce : nonces) {
                ccstAssertFalse(generator->checkUniqueness(nonce, false));
            }
            // Reset state
            generator->resetSavedState();
            for (auto nonce : nonces) {
                ccstAssertTrue(generator->checkUniqueness(nonce, true));
            }
            generator->restoreState(saved_state);
            for (auto nonce : nonces) {
                ccstAssertFalse(generator->checkUniqueness(nonce, false));
            }
        }
    }
    
    void testDefaultNonceGeneratorUniqueness()
    {
        auto generator = crypto::DefaultNonceGenerator::getInstance(2, { 64, 8*65536 });
        for (size_t attempt = 0; attempt <= 65535; attempt++) {
            generator->getNonce();
        }
        // validate all 2B  nonces
        for (size_t attempt = 0; attempt <= 65535; attempt++) {
            cc7::U16 attempt_u16 = attempt & 0xFFFF;
            ccstAssertFalse(generator->checkUniqueness(MakeRange(attempt_u16), true));
        }
        ccstMustThrow(crypto::CryptoException, generator->getNonce());
    }
    
    void testCollisionResistantNonceGenerator()
    {
        auto kdf = crypto::KeyDerivation::getInstance("X963KDF-SHA-384");
        for (size_t len = 1; len <= 4; len++) {
            const auto nonce_size = len * 16;
            const auto key_size = 32;
            auto generator = crypto::CollisionResistantNonceGenerator::getInstance(nonce_size, key_size, kdf);
            auto nonces = std::set<ByteArray>();
            for (int i = 0; i < 1000; i++) {
                auto nonce = generator->getNonce();
                //printf("%03d: %s\n", i, nonce.hexString().c_str());
                ccstAssertEqual(nonce_size, nonce.size());
                if (nonces.find(nonce) != nonces.end()) {
                    ccstFailure("Failed at iteration %d, size %d : %s", i, (int)nonce_size, nonce.hexString().c_str());
                }
                nonces.insert(nonce);
            }
            for (auto nonce : nonces) {
                ccstAssertFalse(generator->checkUniqueness(nonce, false));
            }
            // Save state
            auto saved_state = generator->saveState();
            //printf("state: %s\n", saved_state.hexString().c_str());
            ccstAssertTrue(saved_state.size() >= key_size * 1000);
            // Not modified after save
            for (auto nonce : nonces) {
                ccstAssertFalse(generator->checkUniqueness(nonce, false));
            }
            // Reset state
            generator->resetSavedState();
            for (auto nonce : nonces) {
                ccstAssertTrue(generator->checkUniqueness(nonce, true));
            }
            generator->restoreState(saved_state);
            for (auto nonce : nonces) {
                ccstAssertFalse(generator->checkUniqueness(nonce, false));
            }
        }
    }
    
    void testSimpleNonceGenerator()
    {
        for (size_t len = 1; len <= 4; len++) {
            const auto nonce_size = len * 16;
            auto generator = crypto::SimpleNonceGenerator::getInstance(nonce_size);
            for (int i = 0; i < 1000; i++) {
                auto nonce = generator->getNonce();
                ccstAssertEqual(nonce_size, nonce.size());
            }
        }
    }
};

CC7_CREATE_UNIT_TEST(NonceGeneratorTests, "cc7")
    
} // cc7::tests
} // cc7
