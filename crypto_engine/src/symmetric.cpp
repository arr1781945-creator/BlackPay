/**
 * symmetric.cpp
 * AES-256-GCM, ChaCha20-Poly1305, and HKDF-SHA512 implementations
 * via OpenSSL 3.x EVP API.
 */

#include "symmetric.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdexcept>
#include <cstring>

namespace blackpay::crypto {

// ─── Helpers ──────────────────────────────────────────────────────────────────

static SecureBuffer random_bytes(std::size_t len) {
    SecureBuffer buf(len);
    if (RAND_bytes(buf.data(), static_cast<int>(len)) != 1) {
        throw std::runtime_error("RAND_bytes failed — entropy source unavailable");
    }
    return buf;
}

static AEADResult aead_encrypt(const EVP_CIPHER* cipher,
                               const SecureBuffer& key,
                               std::size_t nonce_len,
                               std::size_t tag_len,
                               const SecureBuffer& plaintext,
                               const SecureBuffer& aad) {
    SecureBuffer nonce = random_bytes(nonce_len);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    struct CtxGuard {
        EVP_CIPHER_CTX* ctx;
        ~CtxGuard() { EVP_CIPHER_CTX_free(ctx); }
    } guard{ctx};

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (cipher) failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nonce_len), nullptr) != 1)
        throw std::runtime_error("AEAD set IV len failed");

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");

    if (!aad.empty()) {
        int outl = 0;
        if (EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("AAD update failed");
    }

    SecureBuffer ciphertext_buf(plaintext.size() + tag_len);
    int outl = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext_buf.data(), &outl,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
            throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int final_outl = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext_buf.data() + outl, &final_outl) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            static_cast<int>(tag_len),
                            ciphertext_buf.data() + outl + final_outl) != 1)
        throw std::runtime_error("Get tag failed");

    std::size_t ct_len = static_cast<std::size_t>(outl + final_outl) + tag_len;
    SecureBuffer final_ct(ciphertext_buf.data(), ct_len);

    return AEADResult{std::move(final_ct), std::move(nonce)};
}

static SecureBuffer aead_decrypt(const EVP_CIPHER* cipher,
                                 const SecureBuffer& key,
                                 std::size_t tag_len,
                                 const SecureBuffer& nonce,
                                 const SecureBuffer& ciphertext,
                                 const SecureBuffer& aad) {
    if (ciphertext.size() < tag_len)
        throw std::invalid_argument("Ciphertext too short");

    std::size_t ct_len = ciphertext.size() - tag_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    struct CtxGuard {
        EVP_CIPHER_CTX* ctx;
        ~CtxGuard() { EVP_CIPHER_CTX_free(ctx); }
    } guard{ctx};

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1)
        throw std::runtime_error("AEAD set IV len failed");

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex (key/iv) failed");

    if (!aad.empty()) {
        int outl = 0;
        if (EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("AAD update failed");
    }

    SecureBuffer plaintext(ct_len + 16);
    int outl = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outl,
                              ciphertext.data(),
                              static_cast<int>(ct_len)) != 1)
            throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    // Set expected tag — const_cast safe: OpenSSL reads it
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(tag_len),
                            const_cast<uint8_t*>(ciphertext.data() + ct_len)) != 1)
        throw std::runtime_error("Set tag failed");

    int final_outl = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outl, &final_outl) != 1)
        throw std::runtime_error("Authentication failed — tag mismatch");

    return SecureBuffer(plaintext.data(),
                        static_cast<std::size_t>(outl + final_outl));
}

// ─── AES-256-GCM ──────────────────────────────────────────────────────────────

AEADResult AES256GCM::encrypt(const SecureBuffer& key,
                               const SecureBuffer& plaintext,
                               const SecureBuffer& aad) {
    if (key.size() != KEY_LEN)
        throw std::invalid_argument("AES-256-GCM key must be 32 bytes");
    return aead_encrypt(EVP_aes_256_gcm(), key, NONCE_LEN, TAG_LEN, plaintext, aad);
}

SecureBuffer AES256GCM::decrypt(const SecureBuffer& key,
                                const SecureBuffer& nonce,
                                const SecureBuffer& ciphertext,
                                const SecureBuffer& aad) {
    if (key.size() != KEY_LEN)
        throw std::invalid_argument("AES-256-GCM key must be 32 bytes");
    if (nonce.size() != NONCE_LEN)
        throw std::invalid_argument("AES-256-GCM nonce must be 12 bytes");
    return aead_decrypt(EVP_aes_256_gcm(), key, TAG_LEN, nonce, ciphertext, aad);
}

SecureBuffer AES256GCM::generate_key()   { return random_bytes(KEY_LEN); }
SecureBuffer AES256GCM::generate_nonce() { return random_bytes(NONCE_LEN); }

// ─── ChaCha20-Poly1305 ────────────────────────────────────────────────────────

AEADResult ChaCha20Poly1305::encrypt(const SecureBuffer& key,
                                      const SecureBuffer& plaintext,
                                      const SecureBuffer& aad) {
    if (key.size() != KEY_LEN)
        throw std::invalid_argument("ChaCha20-Poly1305 key must be 32 bytes");
    return aead_encrypt(EVP_chacha20_poly1305(), key, NONCE_LEN, TAG_LEN,
                        plaintext, aad);
}

SecureBuffer ChaCha20Poly1305::decrypt(const SecureBuffer& key,
                                        const SecureBuffer& nonce,
                                        const SecureBuffer& ciphertext,
                                        const SecureBuffer& aad) {
    if (key.size() != KEY_LEN)
        throw std::invalid_argument("ChaCha20-Poly1305 key must be 32 bytes");
    if (nonce.size() != NONCE_LEN)
        throw std::invalid_argument("ChaCha20-Poly1305 nonce must be 12 bytes");
    return aead_decrypt(EVP_chacha20_poly1305(), key, TAG_LEN, nonce,
                        ciphertext, aad);
}

SecureBuffer ChaCha20Poly1305::generate_key()   { return random_bytes(KEY_LEN); }
SecureBuffer ChaCha20Poly1305::generate_nonce() { return random_bytes(NONCE_LEN); }

// ─── HKDF-SHA512 ──────────────────────────────────────────────────────────────

SecureBuffer HKDF::derive(const SecureBuffer& ikm,
                          const SecureBuffer& salt,
                          const SecureBuffer& info,
                          std::size_t output_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) throw std::runtime_error("EVP_KDF_fetch HKDF failed");

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) throw std::runtime_error("EVP_KDF_CTX_new failed");

    struct KCtxGuard {
        EVP_KDF_CTX* ctx;
        ~KCtxGuard() { EVP_KDF_CTX_free(ctx); }
    } guard{kctx};

    OSSL_PARAM params[6];
    int idx = 0;

    params[idx++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA512"), 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        const_cast<uint8_t*>(ikm.data()), ikm.size());

    if (!salt.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<uint8_t*>(salt.data()), salt.size());
    }
    if (!info.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<uint8_t*>(info.data()), info.size());
    }
    params[idx] = OSSL_PARAM_END;

    SecureBuffer out(output_len);
    if (EVP_KDF_derive(kctx, out.data(), output_len, params) != 1) {
        throw std::runtime_error("HKDF derivation failed");
    }
    return out;
}

SecureBuffer HKDF::derive_aes_key(const SecureBuffer& shared_secret,
                                   const SecureBuffer& info) {
    SecureBuffer salt(0); // zero-length salt → HKDF uses HashLen zeros
    return derive(shared_secret, salt, info, 32);
}

} // namespace blackpay::crypto
