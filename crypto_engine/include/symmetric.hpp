#pragma once
/**
 * symmetric.hpp
 * AES-256-GCM and ChaCha20-Poly1305 AEAD encryption/decryption,
 * plus HKDF-SHA512 key derivation. All via OpenSSL 3.x EVP API.
 */

#include "secure_memory.hpp"
#include <cstdint>

namespace blackpay::crypto {

// ─── AEAD result ──────────────────────────────────────────────────────────────

struct AEADResult {
    SecureBuffer ciphertext; ///< ciphertext || tag (16 bytes appended)
    SecureBuffer nonce;      ///< randomly generated nonce
};

// ─── AES-256-GCM ──────────────────────────────────────────────────────────────

/**
 * AES-256-GCM authenticated encryption.
 *
 * Key must be exactly 32 bytes.
 * Nonce is 12 bytes, randomly generated if not provided.
 * Authentication tag (16 bytes) is appended to ciphertext in result.
 */
class AES256GCM {
public:
    static constexpr std::size_t KEY_LEN   = 32;
    static constexpr std::size_t NONCE_LEN = 12;
    static constexpr std::size_t TAG_LEN   = 16;

    /**
     * Encrypt plaintext with optional additional authenticated data (AAD).
     *
     * @param key       32-byte symmetric key
     * @param plaintext Data to encrypt
     * @param aad       Additional authenticated data (may be empty)
     * @return AEADResult containing ciphertext+tag and nonce
     */
    static AEADResult encrypt(const SecureBuffer& key,
                              const SecureBuffer& plaintext,
                              const SecureBuffer& aad = SecureBuffer(0));

    /**
     * Decrypt and authenticate ciphertext.
     *
     * @param key        32-byte symmetric key
     * @param nonce      12-byte nonce from encryption
     * @param ciphertext Ciphertext || tag bytes
     * @param aad        Additional authenticated data (must match encryption)
     * @return Decrypted plaintext
     * @throws std::runtime_error if authentication fails
     */
    static SecureBuffer decrypt(const SecureBuffer& key,
                                const SecureBuffer& nonce,
                                const SecureBuffer& ciphertext,
                                const SecureBuffer& aad = SecureBuffer(0));

    /** Generate a cryptographically random 32-byte key. */
    static SecureBuffer generate_key();

    /** Generate a cryptographically random 12-byte nonce. */
    static SecureBuffer generate_nonce();
};

// ─── ChaCha20-Poly1305 ────────────────────────────────────────────────────────

/**
 * ChaCha20-Poly1305 authenticated encryption (RFC 8439).
 *
 * Key: 32 bytes. Nonce: 12 bytes. Tag: 16 bytes.
 */
class ChaCha20Poly1305 {
public:
    static constexpr std::size_t KEY_LEN   = 32;
    static constexpr std::size_t NONCE_LEN = 12;
    static constexpr std::size_t TAG_LEN   = 16;

    static AEADResult encrypt(const SecureBuffer& key,
                              const SecureBuffer& plaintext,
                              const SecureBuffer& aad = SecureBuffer(0));

    static SecureBuffer decrypt(const SecureBuffer& key,
                                const SecureBuffer& nonce,
                                const SecureBuffer& ciphertext,
                                const SecureBuffer& aad = SecureBuffer(0));

    static SecureBuffer generate_key();
    static SecureBuffer generate_nonce();
};

// ─── HKDF-SHA512 ──────────────────────────────────────────────────────────────

/**
 * HKDF (RFC 5869) using SHA-512.
 * Used for key derivation from shared secrets and input key material.
 */
class HKDF {
public:
    /**
     * Derive a key of `output_len` bytes.
     *
     * @param ikm        Input key material
     * @param salt       Optional salt (use empty SecureBuffer for no salt)
     * @param info       Context/application string
     * @param output_len Desired output length in bytes (max 8160)
     * @return Derived key material
     */
    static SecureBuffer derive(const SecureBuffer& ikm,
                               const SecureBuffer& salt,
                               const SecureBuffer& info,
                               std::size_t output_len);

    /**
     * Convenience: derive a 32-byte AES key from shared secret.
     */
    static SecureBuffer derive_aes_key(const SecureBuffer& shared_secret,
                                       const SecureBuffer& info);
};

} // namespace blackpay::crypto
