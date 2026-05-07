#pragma once
/**
 * pqc_engine.hpp
 * Post-Quantum Cryptography engine — algorithm-agile KEM and signature
 * operations via liboqs. Supports all NIST PQC standardised and candidate
 * algorithms.
 */

#include "secure_memory.hpp"
#include <string>
#include <vector>
#include <unordered_map>

namespace blackpay::crypto {

// ─── Result types ─────────────────────────────────────────────────────────────

struct KEMKeyPair {
    SecureBuffer public_key;
    SecureBuffer secret_key;
};

struct KEMResult {
    SecureBuffer ciphertext;
    SecureBuffer shared_secret;
};

struct SigKeyPair {
    SecureBuffer public_key;
    SecureBuffer secret_key;
};

struct AlgorithmInfo {
    std::string name;
    std::size_t public_key_len;
    std::size_t secret_key_len;
    std::size_t ciphertext_len;   // KEM only
    std::size_t shared_secret_len;// KEM only
    std::size_t sig_len;          // SIG only
    bool is_kem;
    bool bsi_compliant;
    bool nist_standardised;
};

// ─── KEM engine ───────────────────────────────────────────────────────────────

/**
 * PQC Key Encapsulation Mechanism engine.
 *
 * Supported algorithms (liboqs identifiers):
 *   KEM: ML-KEM-512, ML-KEM-768, ML-KEM-1024,
 *        FrodoKEM-640-AES, FrodoKEM-976-AES, FrodoKEM-1344-AES,
 *        eFrodoKEM-640-AES, eFrodoKEM-976-AES, eFrodoKEM-1344-AES,
 *        BIKE-L1, BIKE-L2, BIKE-L3,
 *        HQC-128, HQC-192, HQC-256,
 *        Classic-McEliece-348864, Classic-McEliece-460896,
 *        Classic-McEliece-6688128, Classic-McEliece-8192128
 */
class PQCKemEngine {
public:
    explicit PQCKemEngine(const std::string& algorithm);
    ~PQCKemEngine();

    PQCKemEngine(const PQCKemEngine&) = delete;
    PQCKemEngine& operator=(const PQCKemEngine&) = delete;

    /** Generate a fresh keypair. */
    KEMKeyPair keygen() const;

    /** Encapsulate: produce ciphertext + shared_secret for given public key. */
    KEMResult encapsulate(const SecureBuffer& public_key) const;

    /** Decapsulate: recover shared_secret from ciphertext + secret key. */
    SecureBuffer decapsulate(const SecureBuffer& ciphertext,
                             const SecureBuffer& secret_key) const;

    AlgorithmInfo info() const;
    const std::string& algorithm() const noexcept { return algorithm_; }

    /** List all supported KEM algorithm names. */
    static std::vector<std::string> supported_algorithms();

private:
    std::string algorithm_;
    struct OQS_KEM* kem_{nullptr};
};

// ─── Signature engine ─────────────────────────────────────────────────────────

/**
 * PQC Digital Signature engine.
 *
 * Supported algorithms:
 *   SIG: ML-DSA-44, ML-DSA-65, ML-DSA-87,
 *        Falcon-512, Falcon-1024,
 *        SPHINCS+-SHA2-128f-simple, SPHINCS+-SHA2-192f-simple,
 *        SPHINCS+-SHA2-256f-simple, (all SLH-DSA variants),
 *        MAYO-1, MAYO-2, MAYO-3, MAYO-5,
 *        CROSS-rsdp-128-balanced, (all CROSS variants),
 *        OV-Ip, OV-III, OV-V,
 *        SNOVA_24_5_4_SSK, (all SNOVA variants)
 */
class PQCSigEngine {
public:
    explicit PQCSigEngine(const std::string& algorithm);
    ~PQCSigEngine();

    PQCSigEngine(const PQCSigEngine&) = delete;
    PQCSigEngine& operator=(const PQCSigEngine&) = delete;

    /** Generate a fresh signing keypair. */
    SigKeyPair keygen() const;

    /** Sign message with secret key. Returns signature bytes. */
    SecureBuffer sign(const SecureBuffer& message,
                      const SecureBuffer& secret_key) const;

    /** Verify signature. Returns true on success. Constant-time. */
    bool verify(const SecureBuffer& message,
                const SecureBuffer& signature,
                const SecureBuffer& public_key) const noexcept;

    AlgorithmInfo info() const;
    const std::string& algorithm() const noexcept { return algorithm_; }

    static std::vector<std::string> supported_algorithms();

private:
    std::string algorithm_;
    struct OQS_SIG* sig_{nullptr};
};

// ─── Algorithm registry ────────────────────────────────────────────────────────

/**
 * Central registry mapping algorithm names to metadata.
 * Used for per-tenant algorithm selection and compliance checks.
 */
class AlgorithmRegistry {
public:
    static const AlgorithmRegistry& instance();

    const AlgorithmInfo* lookup_kem(const std::string& name) const noexcept;
    const AlgorithmInfo* lookup_sig(const std::string& name) const noexcept;

    std::vector<std::string> bsi_compliant_kems() const;
    std::vector<std::string> bsi_compliant_sigs() const;
    std::vector<std::string> nist_standardised_kems() const;
    std::vector<std::string> nist_standardised_sigs() const;

private:
    AlgorithmRegistry();
    std::unordered_map<std::string, AlgorithmInfo> kem_registry_;
    std::unordered_map<std::string, AlgorithmInfo> sig_registry_;
};

} // namespace blackpay::crypto
