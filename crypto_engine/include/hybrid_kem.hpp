#pragma once
/**
 * hybrid_kem.hpp
 * Hybrid KEM: X25519 (classical) + ML-KEM-1024 (post-quantum).
 *
 * Follows BSI TR-02102-1 hybrid construction:
 *   shared_secret = HKDF-SHA512(X25519_ss || ML-KEM_ss, info)
 *
 * This ensures security as long as EITHER component remains unbroken —
 * classical security against current adversaries, quantum-safe for future ones.
 */

#include "secure_memory.hpp"
#include <string>

namespace blackpay::crypto {

// ─── Key pair types ───────────────────────────────────────────────────────────

struct HybridPublicKey {
    SecureBuffer x25519_pk;    ///< 32-byte X25519 public key
    SecureBuffer mlkem_pk;     ///< ML-KEM-1024 public key
    std::vector<uint8_t> serialize() const;
    static HybridPublicKey deserialize(const std::vector<uint8_t>& bytes);
};

struct HybridSecretKey {
    SecureBuffer x25519_sk;    ///< 32-byte X25519 secret key
    SecureBuffer mlkem_sk;     ///< ML-KEM-1024 secret key
    std::vector<uint8_t> serialize() const;
    static HybridSecretKey deserialize(const std::vector<uint8_t>& bytes);
};

struct HybridKeyPair {
    HybridPublicKey  public_key;
    HybridSecretKey  secret_key;
};

struct HybridCiphertext {
    SecureBuffer x25519_eph;   ///< 32-byte ephemeral X25519 public key
    SecureBuffer mlkem_ct;     ///< ML-KEM-1024 ciphertext
    std::vector<uint8_t> serialize() const;
    static HybridCiphertext deserialize(const std::vector<uint8_t>& bytes);
};

struct HybridEncapResult {
    HybridCiphertext ciphertext;
    SecureBuffer     shared_secret; ///< 32-byte derived key (HKDF output)
};

// ─── Hybrid KEM ───────────────────────────────────────────────────────────────

/**
 * X25519 + ML-KEM-1024 hybrid KEM engine.
 *
 * Key generation, encapsulation, and decapsulation are all implemented
 * using constant-time operations at the C++ layer.
 *
 * The combined shared secret is:
 *   HKDF-SHA512(X25519_ss || ML-KEM-1024_ss,
 *               salt="BlackPay-HybridKEM-v1",
 *               info=context_label,
 *               L=32)
 */
class HybridKEM {
public:
    explicit HybridKEM(const std::string& context_label = "BlackPay-HybridKEM-v1");

    /** Generate a hybrid keypair. */
    HybridKeyPair keygen() const;

    /**
     * Encapsulate — generate shared secret for recipient's public key.
     *
     * @param recipient_pk Recipient's hybrid public key
     * @return Ciphertext + 32-byte shared secret
     */
    HybridEncapResult encapsulate(const HybridPublicKey& recipient_pk) const;

    /**
     * Decapsulate — recover shared secret from ciphertext.
     *
     * @param ciphertext  Hybrid ciphertext from encapsulate()
     * @param secret_key  Recipient's hybrid secret key
     * @return 32-byte shared secret
     */
    SecureBuffer decapsulate(const HybridCiphertext& ciphertext,
                             const HybridSecretKey& secret_key) const;

    const std::string& context_label() const noexcept { return context_label_; }

private:
    std::string context_label_;

    /** Perform X25519 Diffie-Hellman. */
    SecureBuffer x25519_dh(const SecureBuffer& sk, const SecureBuffer& pk) const;

    /** Combine two shared secrets via HKDF. */
    SecureBuffer combine_secrets(const SecureBuffer& x25519_ss,
                                 const SecureBuffer& mlkem_ss) const;
};

} // namespace blackpay::crypto
