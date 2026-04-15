/*
 * Copyright 2026 Wultra s.r.o.
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

#include <cc7/crypto/X509.h>
#include "CryptoPrivate.h"
#include "alg/ECKeyPair.h"

namespace cc7::crypto {

// MARK: - CSR

static void addSANExtensions(const X509Req& req, const std::vector<std::string>& san_items)
{
    if (san_items.empty()) {
        return;
    }
    
    std::string san_list = stringJoin(san_items, ",");
    
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);

    // Build extension object
    auto ext = X509Extension::take(X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san_list.c_str()));
    if (!ext) {
        throw CryptoException("Failed to create X509 SAN extension");
    }
    // Build stack
    auto ext_stack = X509ExtensionStack::empty();
    if (!ext_stack) {
        throw CryptoException("Failed to create X509 SAN extension stack");
    }
    // push extension to stack.
    if (sk_X509_EXTENSION_push(ext_stack, ext) == 0) {
        throw CryptoException("Failed to push SAN extension into stack");
    }
    // The extension is added to stack, so X509Extension should no longer manage the instance.
    // Otherwise double memory release would occur.
    ext.release();
    
    // Finally, add extension stack into CSR request
    if (X509_REQ_add_extensions(req, ext_stack) != 1) {
        throw CryptoException("Failed to add SAN extension into CSR");
    }
}

static void addDNItems(const X509Name& name, const std::map<std::string, std::string> &dn_items)
{
    for (const auto& [key, value] : dn_items) {
        if (key.empty()) {
            throw std::invalid_argument("DN item should not have empty key");
        }
        if (value.empty()) {
            // Skip empty value
            continue;
        }
        if (1 != X509_NAME_add_entry_by_txt(name, key.c_str(), MBSTRING_UTF8,
                                            reinterpret_cast<const unsigned char*>(value.c_str()),
                                            static_cast<int>(value.size()),
                                            -1, 0)) {
            throw CryptoException("Adding DN name failed for field: " + key);
        }
    }
}

static void signCSR(const EVPKeyPair& pkey, const std::string& pkey_alg, const X509Req& req)
{
    auto mctx = EVPMDContext::empty();
    const EVP_MD * digest = nullptr;
    bool failure = false;
    if (stringHasPrefix(pkey_alg, "P-")) {
        // For P-XXX curves, select an appropriate hash.
        if (pkey_alg == ECCurveSpec::P_256.name) {
            digest = EVP_sha256();
        } else if (pkey_alg == ECCurveSpec::P_384.name) {
            digest = EVP_sha384();
        } else if (pkey_alg == ECCurveSpec::P_521.name) {
            digest = EVP_sha512();
        } else {
            failure = true;
        }
    } else {
        // For algorithms like ML-DSA, there isn't a traditional external digest.
        auto is_supported_alg = stringHasPrefix(pkey_alg, "ML-DSA-");
        // If algorithm is not supported, then report an error.
        failure = !is_supported_alg;
    }
    
    if (failure) {
        throw CryptoException("Cannot determine digest for key type: " + pkey_alg);
    }
    // Set key to request
    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        throw CryptoException("Failed to set private key to CSR");
    }
    // Do sign
    if (X509_REQ_sign(req, pkey, digest) <= 0) {
        throw CryptoException("Failed to sign CSR");
    }
}

std::string X509::createCSR(const PrivateKey& private_key, const std::map<std::string, std::string> &dn_items, const std::vector<std::string> &san_items)
{
    auto pkey = getLLKey(private_key, true);
    
    auto req = X509Req::empty();
    if (!req) {
        throw CryptoException("Failed to create X509_REQ object");
    }
    auto name = X509Name::empty();
    if (!name) {
        throw CryptoException("Failed to create X509_NAME object");
    }
    // Add DN items
    addDNItems(name, dn_items);
    
    // Add SAN extension
    addSANExtensions(req, san_items);
 
    if (X509_REQ_set_subject_name(req, name) != 1) {
        throw CryptoException("Failed to set subject name to CSR");
    }
    
    // Do sign
    signCSR(pkey, private_key.getKeyType(), req);
    
    // So far so good, prepare "memory" BIO object
    auto bio = OSSLBIO::take(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw CryptoException("Failed to allocate memory buffer for CSR output");
    }
    
    if (PEM_write_bio_X509_REQ(bio, req) != 1) {
        throw CryptoException("Failed to write CSR into PEM format");
    }
    // Extract data from BIO
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (!bptr) {
        throw CryptoException("BIO_get_mem_ptr failed");
    }
    
    // Finally return string with CSR in PEM format
    return std::string(bptr->data, bptr->length);
}

} // namespace cc7::crypto
