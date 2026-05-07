#pragma once
/**
 * zk_engine.hpp
 * Zero-Knowledge proof abstraction layer.
 *
 * Provides Schnorr-style sigma proofs over Curve25519 for:
 *   - Payment amount range proofs (Bulletproofs-style commitment)
 *   - Identity proofs (proof of knowledge of secret key)
 *   - Balance proofs (prove balance >= amount without revealing balance)
 *
 * All operations are constant-time. No heap allocation of sensitive material
 * outside SecureBuffer.
 */

#include "secure_memory.hpp"
#include <cstdint>
#include <vector>
#include <string>

namespace blackpay::crypto::zk {

// ─── Commitment ───────────────────────────────────────────────────────────────

/**
 * Pedersen commitment: C = v*G + r*H
 * where G, H are independent generators on Curve25519.
 */
struct Commitment {
    SecureBuffer value;   ///< 32-byte commitment point
    SecureBuffer blinding; ///< 32-byte blinding factor (secret)

    std::vector<uint8_t> serialize() const;
    static Commitment deserialize(const std::vector<uint8_t>& bytes);
};

/**
 * Commit to a 64-bit value.
 *
 * @param value    Secret value to commit to
 * @param blinding 32-byte random blinding factor (generated if empty)
 * @return Commitment
 */
Commitment commit(uint64_t value, SecureBuffer blinding = SecureBuffer(0));

// ─── Range proof ──────────────────────────────────────────────────────────────

struct RangeProof {
    SecureBuffer proof_bytes; ///< Serialised Bulletproof-style range proof
    Commitment   commitment;  ///< Commitment to the proven value
};

/**
 * Prove that committed value lies in [0, 2^64).
 * Used for payment amount confidentiality.
 *
 * @param value    Value to prove range for
 * @param blinding Blinding factor used in commitment
 * @return RangeProof
 */
RangeProof prove_range(uint64_t value, const SecureBuffer& blinding);

/**
 * Verify range proof.
 *
 * @param proof Range proof to verify
 * @return true if valid
 */
bool verify_range(const RangeProof& proof) noexcept;

// ─── Identity proof (Schnorr) ─────────────────────────────────────────────────

struct SchnorrProof {
    SecureBuffer commitment_r;  ///< R = r*G (32 bytes)
    SecureBuffer response_s;    ///< s = r + c*x (32 bytes)
    SecureBuffer challenge_c;   ///< Fiat-Shamir challenge (32 bytes)
};

/**
 * Prove knowledge of secret key x for public key X = x*G (Schnorr PoK).
 *
 * @param secret_key 32-byte scalar
 * @param public_key 32-byte point (must equal secret_key * G)
 * @param message    Optional binding message for domain separation
 * @return SchnorrProof
 */
SchnorrProof prove_identity(const SecureBuffer& secret_key,
                            const SecureBuffer& public_key,
                            const SecureBuffer& message);

/**
 * Verify Schnorr identity proof.
 *
 * @param proof      Proof to verify
 * @param public_key Claimed public key
 * @param message    Binding message used during proof generation
 * @return true if valid
 */
bool verify_identity(const SchnorrProof& proof,
                     const SecureBuffer& public_key,
                     const SecureBuffer& message) noexcept;

// ─── Balance proof ────────────────────────────────────────────────────────────

struct BalanceProof {
    Commitment   balance_commitment;   ///< Commitment to balance
    Commitment   amount_commitment;    ///< Commitment to amount
    RangeProof   difference_proof;     ///< Proves balance - amount >= 0
    SchnorrProof ownership_proof;      ///< Proves knowledge of blinding factor
};

/**
 * Prove balance >= amount without revealing either value.
 *
 * @param balance          Actual balance (secret)
 * @param amount           Payment amount (secret)
 * @param balance_blinding Blinding for balance commitment
 * @param amount_blinding  Blinding for amount commitment
 * @return BalanceProof
 */
BalanceProof prove_sufficient_balance(uint64_t balance,
                                      uint64_t amount,
                                      const SecureBuffer& balance_blinding,
                                      const SecureBuffer& amount_blinding);

/**
 * Verify balance proof.
 */
bool verify_sufficient_balance(const BalanceProof& proof) noexcept;

// ─── Serialization helpers ────────────────────────────────────────────────────

std::vector<uint8_t> serialize_schnorr(const SchnorrProof& proof);
SchnorrProof deserialize_schnorr(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> serialize_balance_proof(const BalanceProof& proof);
BalanceProof deserialize_balance_proof(const std::vector<uint8_t>& bytes);

} // namespace blackpay::crypto::zk
