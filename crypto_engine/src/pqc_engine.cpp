/**
 * pqc_engine.cpp
 * Post-Quantum Cryptography engine implementation via liboqs.
 * All KEM and signature operations are algorithm-agile.
 */

#include "pqc_engine.hpp"
#include "secure_memory.hpp"
#include <oqs/oqs.h>
#include <stdexcept>
#include <cstring>

namespace blackpay::crypto {

// ─── PQCKemEngine ─────────────────────────────────────────────────────────────

PQCKemEngine::PQCKemEngine(const std::string& algorithm)
    : algorithm_(algorithm) {
    kem_ = OQS_KEM_new(algorithm.c_str());
    if (!kem_) {
        throw std::invalid_argument("Unsupported KEM algorithm: " + algorithm);
    }
}

PQCKemEngine::~PQCKemEngine() {
    if (kem_) {
        OQS_KEM_free(kem_);
        kem_ = nullptr;
    }
}

KEMKeyPair PQCKemEngine::keygen() const {
    KEMKeyPair kp{SecureBuffer(kem_->length_public_key),
                  SecureBuffer(kem_->length_secret_key)};
    OQS_STATUS rc = OQS_KEM_keypair(kem_, kp.public_key.data(), kp.secret_key.data());
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("KEM keygen failed for: " + algorithm_);
    }
    return kp;
}

KEMResult PQCKemEngine::encapsulate(const SecureBuffer& public_key) const {
    if (public_key.size() != kem_->length_public_key) {
        throw std::invalid_argument("Invalid public key length for " + algorithm_);
    }
    KEMResult result{SecureBuffer(kem_->length_ciphertext),
                     SecureBuffer(kem_->length_shared_secret)};
    OQS_STATUS rc = OQS_KEM_encaps(
        kem_,
        result.ciphertext.data(),
        result.shared_secret.data(),
        public_key.data()
    );
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("KEM encapsulation failed for: " + algorithm_);
    }
    return result;
}

SecureBuffer PQCKemEngine::decapsulate(const SecureBuffer& ciphertext,
                                       const SecureBuffer& secret_key) const {
    if (ciphertext.size() != kem_->length_ciphertext) {
        throw std::invalid_argument("Invalid ciphertext length for " + algorithm_);
    }
    if (secret_key.size() != kem_->length_secret_key) {
        throw std::invalid_argument("Invalid secret key length for " + algorithm_);
    }
    SecureBuffer shared_secret(kem_->length_shared_secret);
    OQS_STATUS rc = OQS_KEM_decaps(
        kem_,
        shared_secret.data(),
        ciphertext.data(),
        secret_key.data()
    );
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("KEM decapsulation failed for: " + algorithm_);
    }
    return shared_secret;
}

AlgorithmInfo PQCKemEngine::info() const {
    const auto* reg = AlgorithmRegistry::instance().lookup_kem(algorithm_);
    if (reg) return *reg;
    return AlgorithmInfo{
        algorithm_,
        kem_->length_public_key,
        kem_->length_secret_key,
        kem_->length_ciphertext,
        kem_->length_shared_secret,
        0, true, false, false
    };
}

std::vector<std::string> PQCKemEngine::supported_algorithms() {
    return {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES",
        "eFrodoKEM-640-AES", "eFrodoKEM-976-AES", "eFrodoKEM-1344-AES",
        "BIKE-L1", "BIKE-L2", "BIKE-L3",
        "HQC-128", "HQC-192", "HQC-256",
        "Classic-McEliece-348864", "Classic-McEliece-460896",
        "Classic-McEliece-6688128", "Classic-McEliece-8192128",
    };
}

// ─── PQCSigEngine ─────────────────────────────────────────────────────────────

PQCSigEngine::PQCSigEngine(const std::string& algorithm)
    : algorithm_(algorithm) {
    sig_ = OQS_SIG_new(algorithm.c_str());
    if (!sig_) {
        throw std::invalid_argument("Unsupported SIG algorithm: " + algorithm);
    }
}

PQCSigEngine::~PQCSigEngine() {
    if (sig_) {
        OQS_SIG_free(sig_);
        sig_ = nullptr;
    }
}

SigKeyPair PQCSigEngine::keygen() const {
    SigKeyPair kp{SecureBuffer(sig_->length_public_key),
                  SecureBuffer(sig_->length_secret_key)};
    OQS_STATUS rc = OQS_SIG_keypair(sig_, kp.public_key.data(), kp.secret_key.data());
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("SIG keygen failed for: " + algorithm_);
    }
    return kp;
}

SecureBuffer PQCSigEngine::sign(const SecureBuffer& message,
                                const SecureBuffer& secret_key) const {
    if (secret_key.size() != sig_->length_secret_key) {
        throw std::invalid_argument("Invalid secret key length for " + algorithm_);
    }
    SecureBuffer signature(sig_->length_signature);
    std::size_t sig_len = sig_->length_signature;
    OQS_STATUS rc = OQS_SIG_sign(
        sig_,
        signature.data(), &sig_len,
        message.data(), message.size(),
        secret_key.data()
    );
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("SIG signing failed for: " + algorithm_);
    }
    // Trim to actual signature length
    if (sig_len < signature.size()) {
        SecureBuffer trimmed(signature.data(), sig_len);
        return trimmed;
    }
    return signature;
}

bool PQCSigEngine::verify(const SecureBuffer& message,
                          const SecureBuffer& signature,
                          const SecureBuffer& public_key) const noexcept {
    if (public_key.size() != sig_->length_public_key) return false;
    OQS_STATUS rc = OQS_SIG_verify(
        sig_,
        message.data(), message.size(),
        signature.data(), signature.size(),
        public_key.data()
    );
    return rc == OQS_SUCCESS;
}

AlgorithmInfo PQCSigEngine::info() const {
    const auto* reg = AlgorithmRegistry::instance().lookup_sig(algorithm_);
    if (reg) return *reg;
    return AlgorithmInfo{
        algorithm_,
        sig_->length_public_key,
        sig_->length_secret_key,
        0, 0,
        sig_->length_signature,
        false, false, false
    };
}

std::vector<std::string> PQCSigEngine::supported_algorithms() {
    return {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "Falcon-512", "Falcon-1024",
        "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple",
        "SPHINCS+-SHA2-192f-simple", "SPHINCS+-SHA2-192s-simple",
        "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple",
        "SPHINCS+-SHAKE-128f-simple", "SPHINCS+-SHAKE-128s-simple",
        "SPHINCS+-SHAKE-192f-simple", "SPHINCS+-SHAKE-192s-simple",
        "SPHINCS+-SHAKE-256f-simple", "SPHINCS+-SHAKE-256s-simple",
        "MAYO-1", "MAYO-2", "MAYO-3", "MAYO-5",
        "CROSS-rsdp-128-balanced", "CROSS-rsdp-128-fast", "CROSS-rsdp-128-small",
        "CROSS-rsdp-192-balanced", "CROSS-rsdp-256-balanced",
        "OV-Ip", "OV-III", "OV-V",
        "SNOVA_24_5_4_SSK", "SNOVA_25_8_3_SSK",
    };
}

// ─── AlgorithmRegistry ────────────────────────────────────────────────────────

AlgorithmRegistry::AlgorithmRegistry() {
    // KEM registry
    kem_registry_ = {
        {"ML-KEM-512",    {"ML-KEM-512",    800,  1632,  768,  32, 0, true, true,  true}},
        {"ML-KEM-768",    {"ML-KEM-768",    1184, 2400, 1088,  32, 0, true, true,  true}},
        {"ML-KEM-1024",   {"ML-KEM-1024",   1568, 3168, 1568,  32, 0, true, true,  true}},
        {"FrodoKEM-640-AES",  {"FrodoKEM-640-AES",  9616, 19888, 9720, 16, 0, true, true, false}},
        {"FrodoKEM-976-AES",  {"FrodoKEM-976-AES",  15632, 31296,15744, 24, 0, true, true, false}},
        {"FrodoKEM-1344-AES", {"FrodoKEM-1344-AES", 21520, 43088,21632, 32, 0, true, true, false}},
        {"BIKE-L1", {"BIKE-L1", 1541, 3113, 1573, 32, 0, true, false, false}},
        {"BIKE-L3", {"BIKE-L3", 3083, 6275, 3115, 48, 0, true, false, false}},
        {"HQC-128", {"HQC-128", 2249, 2289, 4481, 64, 0, true, false, false}},
        {"HQC-192", {"HQC-192", 4522, 4562, 9026, 64, 0, true, false, false}},
        {"HQC-256", {"HQC-256", 7245, 7285,14469, 64, 0, true, false, false}},
    };

    // SIG registry
    sig_registry_ = {
        {"ML-DSA-44", {"ML-DSA-44", 1312, 2528, 0, 0, 2420, false, true, true}},
        {"ML-DSA-65", {"ML-DSA-65", 1952, 4032, 0, 0, 3309, false, true, true}},
        {"ML-DSA-87", {"ML-DSA-87", 2592, 4896, 0, 0, 4627, false, true, true}},
        {"Falcon-512",  {"Falcon-512",  897,  1281, 0, 0, 666,  false, false, true}},
        {"Falcon-1024", {"Falcon-1024", 1793, 2305, 0, 0, 1280, false, false, true}},
        {"MAYO-1", {"MAYO-1", 1168, 24, 0, 0, 321, false, false, false}},
        {"MAYO-2", {"MAYO-2", 5488, 24, 0, 0, 180, false, false, false}},
    };
}

const AlgorithmRegistry& AlgorithmRegistry::instance() {
    static AlgorithmRegistry reg;
    return reg;
}

const AlgorithmInfo* AlgorithmRegistry::lookup_kem(const std::string& name) const noexcept {
    auto it = kem_registry_.find(name);
    return it != kem_registry_.end() ? &it->second : nullptr;
}

const AlgorithmInfo* AlgorithmRegistry::lookup_sig(const std::string& name) const noexcept {
    auto it = sig_registry_.find(name);
    return it != sig_registry_.end() ? &it->second : nullptr;
}

std::vector<std::string> AlgorithmRegistry::bsi_compliant_kems() const {
    std::vector<std::string> result;
    for (const auto& [name, info] : kem_registry_) {
        if (info.bsi_compliant) result.push_back(name);
    }
    return result;
}

std::vector<std::string> AlgorithmRegistry::nist_standardised_kems() const {
    std::vector<std::string> result;
    for (const auto& [name, info] : kem_registry_) {
        if (info.nist_standardised) result.push_back(name);
    }
    return result;
}

std::vector<std::string> AlgorithmRegistry::bsi_compliant_sigs() const {
    std::vector<std::string> result;
    for (const auto& [name, info] : sig_registry_) {
        if (info.bsi_compliant) result.push_back(name);
    }
    return result;
}

std::vector<std::string> AlgorithmRegistry::nist_standardised_sigs() const {
    std::vector<std::string> result;
    for (const auto& [name, info] : sig_registry_) {
        if (info.nist_standardised) result.push_back(name);
    }
    return result;
}

} // namespace blackpay::crypto
