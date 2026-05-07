/**
 * hybrid_kem.cpp
 * X25519 + ML-KEM-1024 hybrid KEM — BSI TR-02102-1 compliant construction.
 *
 * Combined shared secret:
 *   HKDF-SHA512(X25519_ss || ML-KEM-1024_ss,
 *               salt = context_label,
 *               info = "BlackPay-HybridKEM-combine",
 *               L = 32)
 */

#include "hybrid_kem.hpp"
#include "pqc_engine.hpp"
#include "symmetric.hpp"
#include "secure_memory.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

namespace blackpay::crypto {

// ─── Serialization helpers ────────────────────────────────────────────────────

static void append_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    buf.push_back(static_cast<uint8_t>((v >>  8) & 0xff));
    buf.push_back(static_cast<uint8_t>((v      ) & 0xff));
}

static uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           (static_cast<uint32_t>(p[3]));
}

// HybridPublicKey: [u32 x25519_len][x25519_pk][u32 mlkem_len][mlkem_pk]
std::vector<uint8_t> HybridPublicKey::serialize() const {
    std::vector<uint8_t> out;
    append_u32(out, static_cast<uint32_t>(x25519_pk.size()));
    out.insert(out.end(), x25519_pk.data(), x25519_pk.data() + x25519_pk.size());
    append_u32(out, static_cast<uint32_t>(mlkem_pk.size()));
    out.insert(out.end(), mlkem_pk.data(), mlkem_pk.data() + mlkem_pk.size());
    return out;
}

HybridPublicKey HybridPublicKey::deserialize(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 8) throw std::invalid_argument("HybridPublicKey too short");
    const uint8_t* p = bytes.data();
    uint32_t x25519_len = read_u32(p); p += 4;
    SecureBuffer x25519_pk(p, x25519_len); p += x25519_len;
    uint32_t mlkem_len = read_u32(p); p += 4;
    SecureBuffer mlkem_pk(p, mlkem_len);
    return HybridPublicKey{std::move(x25519_pk), std::move(mlkem_pk)};
}

std::vector<uint8_t> HybridCiphertext::serialize() const {
    std::vector<uint8_t> out;
    append_u32(out, static_cast<uint32_t>(x25519_eph.size()));
    out.insert(out.end(), x25519_eph.data(), x25519_eph.data() + x25519_eph.size());
    append_u32(out, static_cast<uint32_t>(mlkem_ct.size()));
    out.insert(out.end(), mlkem_ct.data(), mlkem_ct.data() + mlkem_ct.size());
    return out;
}

HybridCiphertext HybridCiphertext::deserialize(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 8) throw std::invalid_argument("HybridCiphertext too short");
    const uint8_t* p = bytes.data();
    uint32_t x25519_len = read_u32(p); p += 4;
    SecureBuffer x25519_eph(p, x25519_len); p += x25519_len;
    uint32_t mlkem_len = read_u32(p); p += 4;
    SecureBuffer mlkem_ct(p, mlkem_len);
    return HybridCiphertext{std::move(x25519_eph), std::move(mlkem_ct)};
}

// ─── HybridKEM ────────────────────────────────────────────────────────────────

HybridKEM::HybridKEM(const std::string& context_label)
    : context_label_(context_label) {}

HybridKeyPair HybridKEM::keygen() const {
    // X25519 keypair
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id X25519 failed");

    struct PCtxGuard {
        EVP_PKEY_CTX* ctx;
        ~PCtxGuard() { EVP_PKEY_CTX_free(ctx); }
    } guard{pctx};

    if (EVP_PKEY_keygen_init(pctx) != 1)
        throw std::runtime_error("EVP_PKEY_keygen_init failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1)
        throw std::runtime_error("X25519 keygen failed");

    struct PKeyGuard {
        EVP_PKEY* k;
        ~PKeyGuard() { EVP_PKEY_free(k); }
    } pkg{pkey};

    std::size_t pub_len = 32, priv_len = 32;
    SecureBuffer x25519_pk(pub_len), x25519_sk(priv_len);

    if (EVP_PKEY_get_raw_public_key(pkey, x25519_pk.data(), &pub_len) != 1)
        throw std::runtime_error("Get X25519 public key failed");
    if (EVP_PKEY_get_raw_private_key(pkey, x25519_sk.data(), &priv_len) != 1)
        throw std::runtime_error("Get X25519 private key failed");

    // ML-KEM-1024 keypair
    PQCKemEngine mlkem("ML-KEM-1024");
    auto mlkem_kp = mlkem.keygen();

    HybridPublicKey pub{std::move(x25519_pk), std::move(mlkem_kp.public_key)};
    HybridSecretKey sec{std::move(x25519_sk), std::move(mlkem_kp.secret_key)};

    return HybridKeyPair{std::move(pub), std::move(sec)};
}

SecureBuffer HybridKEM::x25519_dh(const SecureBuffer& sk,
                                   const SecureBuffer& pk) const {
    EVP_PKEY* pkey_sk = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, sk.data(), sk.size());
    if (!pkey_sk) throw std::runtime_error("Rebuild X25519 private key failed");

    EVP_PKEY* pkey_pk = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, pk.data(), pk.size());
    if (!pkey_pk) { EVP_PKEY_free(pkey_sk); throw std::runtime_error("Rebuild X25519 public key failed"); }

    struct PKeyGuard2 {
        EVP_PKEY* sk; EVP_PKEY* pk;
        ~PKeyGuard2() { EVP_PKEY_free(sk); EVP_PKEY_free(pk); }
    } g{pkey_sk, pkey_pk};

    EVP_PKEY_CTX* dh_ctx = EVP_PKEY_CTX_new(pkey_sk, nullptr);
    if (!dh_ctx) throw std::runtime_error("EVP_PKEY_CTX_new for DH failed");

    struct DHCtxGuard {
        EVP_PKEY_CTX* c;
        ~DHCtxGuard() { EVP_PKEY_CTX_free(c); }
    } dhg{dh_ctx};

    if (EVP_PKEY_derive_init(dh_ctx) != 1)
        throw std::runtime_error("EVP_PKEY_derive_init failed");
    if (EVP_PKEY_derive_set_peer(dh_ctx, pkey_pk) != 1)
        throw std::runtime_error("EVP_PKEY_derive_set_peer failed");

    std::size_t ss_len = 32;
    SecureBuffer ss(ss_len);
    if (EVP_PKEY_derive(dh_ctx, ss.data(), &ss_len) != 1)
        throw std::runtime_error("X25519 DH derivation failed");

    return ss;
}

SecureBuffer HybridKEM::combine_secrets(const SecureBuffer& x25519_ss,
                                         const SecureBuffer& mlkem_ss) const {
    // Concatenate: x25519_ss || mlkem_ss
    SecureBuffer ikm(x25519_ss.size() + mlkem_ss.size());
    std::memcpy(ikm.data(), x25519_ss.data(), x25519_ss.size());
    std::memcpy(ikm.data() + x25519_ss.size(), mlkem_ss.data(), mlkem_ss.size());

    // HKDF with context_label as salt
    SecureBuffer salt(reinterpret_cast<const uint8_t*>(context_label_.data()),
                      context_label_.size());
    const std::string info_str = "BlackPay-HybridKEM-combine";
    SecureBuffer info(reinterpret_cast<const uint8_t*>(info_str.data()),
                      info_str.size());

    return HKDF::derive(ikm, salt, info, 32);
}

HybridEncapResult HybridKEM::encapsulate(const HybridPublicKey& recipient_pk) const {
    // Ephemeral X25519 keypair
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) throw std::runtime_error("Ephemeral X25519 ctx failed");
    struct PCtxGuard { EVP_PKEY_CTX* c; ~PCtxGuard(){ EVP_PKEY_CTX_free(c); }} g{pctx};

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY* eph_pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &eph_pkey) != 1)
        throw std::runtime_error("Ephemeral X25519 keygen failed");
    struct PKeyGuard { EVP_PKEY* k; ~PKeyGuard(){ EVP_PKEY_free(k); }} pkg{eph_pkey};

    std::size_t pub_len = 32, priv_len = 32;
    SecureBuffer eph_pk(pub_len), eph_sk(priv_len);
    EVP_PKEY_get_raw_public_key(eph_pkey, eph_pk.data(), &pub_len);
    EVP_PKEY_get_raw_private_key(eph_pkey, eph_sk.data(), &priv_len);

    // X25519 DH
    SecureBuffer x25519_ss = x25519_dh(eph_sk, recipient_pk.x25519_pk);

    // ML-KEM-1024 encaps
    PQCKemEngine mlkem("ML-KEM-1024");
    auto mlkem_result = mlkem.encapsulate(recipient_pk.mlkem_pk);

    // Combine
    SecureBuffer combined = combine_secrets(x25519_ss, mlkem_result.shared_secret);

    HybridCiphertext ct{std::move(eph_pk), std::move(mlkem_result.ciphertext)};
    return HybridEncapResult{std::move(ct), std::move(combined)};
}

SecureBuffer HybridKEM::decapsulate(const HybridCiphertext& ciphertext,
                                     const HybridSecretKey& secret_key) const {
    // X25519 DH (recipient sk, sender eph pk)
    SecureBuffer x25519_ss = x25519_dh(secret_key.x25519_sk, ciphertext.x25519_eph);

    // ML-KEM-1024 decaps
    PQCKemEngine mlkem("ML-KEM-1024");
    SecureBuffer mlkem_ss = mlkem.decapsulate(ciphertext.mlkem_ct, secret_key.mlkem_sk);

    return combine_secrets(x25519_ss, mlkem_ss);
}

} // namespace blackpay::crypto
