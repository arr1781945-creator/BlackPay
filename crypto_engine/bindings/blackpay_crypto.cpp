/**
 * blackpay_crypto.cpp
 * pybind11 bindings — exposes C++ crypto engine to Python/Django.
 *
 * All byte arrays cross the boundary as Python bytes objects.
 * SecureBuffer contents are copied to Python bytes and immediately zeroized
 * after the copy, minimising the lifetime of sensitive data in Python memory.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "pqc_engine.hpp"
#include "symmetric.hpp"
#include "hybrid_kem.hpp"
#include "zk_engine.hpp"
#include "secure_memory.hpp"

namespace py = pybind11;
using namespace blackpay::crypto;

// ─── Conversion helpers ───────────────────────────────────────────────────────

/** bytes → SecureBuffer */
static SecureBuffer from_pybytes(const py::bytes& b) {
    std::string_view sv{b};
    return SecureBuffer(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
}

/** SecureBuffer → bytes (copies, then zeroizes original) */
static py::bytes to_pybytes(SecureBuffer buf) {
    py::bytes result(reinterpret_cast<const char*>(buf.data()), buf.size());
    // buf is zeroized by destructor after this scope
    return result;
}

static py::bytes vec_to_pybytes(const std::vector<uint8_t>& v) {
    return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
}

// ─── Module definition ────────────────────────────────────────────────────────

PYBIND11_MODULE(blackpay_crypto, m) {
    m.doc() = "BlackPay Post-Quantum Cryptography Engine (pybind11)";

    // ── AlgorithmInfo ─────────────────────────────────────────────────────────
    py::class_<AlgorithmInfo>(m, "AlgorithmInfo")
        .def_readonly("name",              &AlgorithmInfo::name)
        .def_readonly("public_key_len",    &AlgorithmInfo::public_key_len)
        .def_readonly("secret_key_len",    &AlgorithmInfo::secret_key_len)
        .def_readonly("ciphertext_len",    &AlgorithmInfo::ciphertext_len)
        .def_readonly("shared_secret_len", &AlgorithmInfo::shared_secret_len)
        .def_readonly("sig_len",           &AlgorithmInfo::sig_len)
        .def_readonly("is_kem",            &AlgorithmInfo::is_kem)
        .def_readonly("bsi_compliant",     &AlgorithmInfo::bsi_compliant)
        .def_readonly("nist_standardised", &AlgorithmInfo::nist_standardised);

    // ── PQC KEM ───────────────────────────────────────────────────────────────
    py::class_<PQCKemEngine>(m, "PQCKemEngine")
        .def(py::init<const std::string&>(), py::arg("algorithm"))
        .def("keygen", [](const PQCKemEngine& self) {
            auto kp = self.keygen();
            return py::make_tuple(
                to_pybytes(std::move(kp.public_key)),
                to_pybytes(std::move(kp.secret_key))
            );
        }, "Returns (public_key_bytes, secret_key_bytes)")
        .def("encapsulate", [](const PQCKemEngine& self, const py::bytes& pk) {
            auto r = self.encapsulate(from_pybytes(pk));
            return py::make_tuple(
                to_pybytes(std::move(r.ciphertext)),
                to_pybytes(std::move(r.shared_secret))
            );
        }, py::arg("public_key"), "Returns (ciphertext_bytes, shared_secret_bytes)")
        .def("decapsulate", [](const PQCKemEngine& self,
                                const py::bytes& ct, const py::bytes& sk) {
            return to_pybytes(self.decapsulate(from_pybytes(ct), from_pybytes(sk)));
        }, py::arg("ciphertext"), py::arg("secret_key"), "Returns shared_secret_bytes")
        .def("info", &PQCKemEngine::info)
        .def_property_readonly("algorithm", &PQCKemEngine::algorithm)
        .def_static("supported_algorithms", &PQCKemEngine::supported_algorithms);

    // ── PQC SIG ───────────────────────────────────────────────────────────────
    py::class_<PQCSigEngine>(m, "PQCSigEngine")
        .def(py::init<const std::string&>(), py::arg("algorithm"))
        .def("keygen", [](const PQCSigEngine& self) {
            auto kp = self.keygen();
            return py::make_tuple(
                to_pybytes(std::move(kp.public_key)),
                to_pybytes(std::move(kp.secret_key))
            );
        }, "Returns (public_key_bytes, secret_key_bytes)")
        .def("sign", [](const PQCSigEngine& self,
                         const py::bytes& msg, const py::bytes& sk) {
            return to_pybytes(self.sign(from_pybytes(msg), from_pybytes(sk)));
        }, py::arg("message"), py::arg("secret_key"), "Returns signature_bytes")
        .def("verify", [](const PQCSigEngine& self,
                           const py::bytes& msg, const py::bytes& sig,
                           const py::bytes& pk) {
            return self.verify(from_pybytes(msg), from_pybytes(sig), from_pybytes(pk));
        }, py::arg("message"), py::arg("signature"), py::arg("public_key"))
        .def("info", &PQCSigEngine::info)
        .def_property_readonly("algorithm", &PQCSigEngine::algorithm)
        .def_static("supported_algorithms", &PQCSigEngine::supported_algorithms);

    // ── AES-256-GCM ───────────────────────────────────────────────────────────
    py::class_<AES256GCM>(m, "AES256GCM")
        .def_static("encrypt", [](const py::bytes& key,
                                   const py::bytes& plaintext,
                                   const py::bytes& aad) {
            SecureBuffer aad_buf = aad.size() > 0 ? from_pybytes(aad) : SecureBuffer(0);
            auto r = AES256GCM::encrypt(from_pybytes(key), from_pybytes(plaintext), aad_buf);
            return py::make_tuple(
                to_pybytes(std::move(r.ciphertext)),
                to_pybytes(std::move(r.nonce))
            );
        }, py::arg("key"), py::arg("plaintext"), py::arg("aad") = py::bytes(""),
           "Returns (ciphertext_with_tag, nonce)")
        .def_static("decrypt", [](const py::bytes& key, const py::bytes& nonce,
                                   const py::bytes& ciphertext, const py::bytes& aad) {
            SecureBuffer aad_buf = aad.size() > 0 ? from_pybytes(aad) : SecureBuffer(0);
            return to_pybytes(AES256GCM::decrypt(
                from_pybytes(key), from_pybytes(nonce),
                from_pybytes(ciphertext), aad_buf));
        }, py::arg("key"), py::arg("nonce"), py::arg("ciphertext"),
           py::arg("aad") = py::bytes(""), "Returns plaintext")
        .def_static("generate_key",   []() { return to_pybytes(AES256GCM::generate_key()); })
        .def_static("generate_nonce", []() { return to_pybytes(AES256GCM::generate_nonce()); })
        .def_readonly_static("KEY_LEN",   &AES256GCM::KEY_LEN)
        .def_readonly_static("NONCE_LEN", &AES256GCM::NONCE_LEN)
        .def_readonly_static("TAG_LEN",   &AES256GCM::TAG_LEN);

    // ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────
    py::class_<ChaCha20Poly1305>(m, "ChaCha20Poly1305")
        .def_static("encrypt", [](const py::bytes& key, const py::bytes& plaintext,
                                   const py::bytes& aad) {
            SecureBuffer aad_buf = aad.size() > 0 ? from_pybytes(aad) : SecureBuffer(0);
            auto r = ChaCha20Poly1305::encrypt(from_pybytes(key), from_pybytes(plaintext), aad_buf);
            return py::make_tuple(
                to_pybytes(std::move(r.ciphertext)),
                to_pybytes(std::move(r.nonce))
            );
        }, py::arg("key"), py::arg("plaintext"), py::arg("aad") = py::bytes(""))
        .def_static("decrypt", [](const py::bytes& key, const py::bytes& nonce,
                                   const py::bytes& ciphertext, const py::bytes& aad) {
            SecureBuffer aad_buf = aad.size() > 0 ? from_pybytes(aad) : SecureBuffer(0);
            return to_pybytes(ChaCha20Poly1305::decrypt(
                from_pybytes(key), from_pybytes(nonce),
                from_pybytes(ciphertext), aad_buf));
        }, py::arg("key"), py::arg("nonce"), py::arg("ciphertext"),
           py::arg("aad") = py::bytes(""))
        .def_static("generate_key",   []() { return to_pybytes(ChaCha20Poly1305::generate_key()); })
        .def_static("generate_nonce", []() { return to_pybytes(ChaCha20Poly1305::generate_nonce()); });

    // ── HKDF ──────────────────────────────────────────────────────────────────
    py::class_<HKDF>(m, "HKDF")
        .def_static("derive", [](const py::bytes& ikm, const py::bytes& salt,
                                  const py::bytes& info, std::size_t output_len) {
            return to_pybytes(HKDF::derive(
                from_pybytes(ikm), from_pybytes(salt),
                from_pybytes(info), output_len));
        }, py::arg("ikm"), py::arg("salt"), py::arg("info"), py::arg("output_len"))
        .def_static("derive_aes_key", [](const py::bytes& ss, const py::bytes& info) {
            return to_pybytes(HKDF::derive_aes_key(from_pybytes(ss), from_pybytes(info)));
        }, py::arg("shared_secret"), py::arg("info"));

    // ── Hybrid KEM ────────────────────────────────────────────────────────────
    py::class_<HybridKEM>(m, "HybridKEM")
        .def(py::init<const std::string&>(),
             py::arg("context_label") = "BlackPay-HybridKEM-v1")
        .def("keygen", [](const HybridKEM& self) {
            auto kp = self.keygen();
            auto pub_bytes = kp.public_key.serialize();
            auto sec_bytes = kp.secret_key.serialize();
            return py::make_tuple(vec_to_pybytes(pub_bytes), vec_to_pybytes(sec_bytes));
        }, "Returns (public_key_bytes, secret_key_bytes)")
        .def("encapsulate", [](const HybridKEM& self, const py::bytes& pk_bytes) {
            auto pk_vec = std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(std::string_view{pk_bytes}.data()),
                reinterpret_cast<const uint8_t*>(std::string_view{pk_bytes}.data()) +
                    py::len(pk_bytes));
            auto pk = HybridPublicKey::deserialize(pk_vec);
            auto result = self.encapsulate(pk);
            auto ct_bytes = result.ciphertext.serialize();
            return py::make_tuple(vec_to_pybytes(ct_bytes),
                                  to_pybytes(std::move(result.shared_secret)));
        }, py::arg("public_key"), "Returns (ciphertext_bytes, shared_secret_bytes)")
        .def("decapsulate", [](const HybridKEM& self,
                                const py::bytes& ct_bytes, const py::bytes& sk_bytes) {
            std::string_view ct_sv{ct_bytes}, sk_sv{sk_bytes};
            auto ct = HybridCiphertext::deserialize(
                std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(ct_sv.data()),
                                     reinterpret_cast<const uint8_t*>(ct_sv.data()) + ct_sv.size()));
            auto sk = HybridSecretKey::deserialize(
                std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sk_sv.data()),
                                     reinterpret_cast<const uint8_t*>(sk_sv.data()) + sk_sv.size()));
            return to_pybytes(self.decapsulate(ct, sk));
        }, py::arg("ciphertext"), py::arg("secret_key"), "Returns shared_secret_bytes");

    // ── ZK engine ─────────────────────────────────────────────────────────────
    py::module_ zk = m.def_submodule("zk", "Zero-Knowledge proof primitives");

    zk.def("prove_identity", [](const py::bytes& sk, const py::bytes& pk,
                                 const py::bytes& msg) {
        auto proof = zk::prove_identity(from_pybytes(sk), from_pybytes(pk),
                                         from_pybytes(msg));
        auto serialised = zk::serialize_schnorr(proof);
        return vec_to_pybytes(serialised);
    }, py::arg("secret_key"), py::arg("public_key"), py::arg("message"),
       "Returns serialised SchnorrProof bytes");

    zk.def("verify_identity", [](const py::bytes& proof_bytes,
                                  const py::bytes& pk, const py::bytes& msg) {
        std::string_view sv{proof_bytes};
        auto proof = zk::deserialize_schnorr(
            std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()),
                                 reinterpret_cast<const uint8_t*>(sv.data()) + sv.size()));
        return zk::verify_identity(proof, from_pybytes(pk), from_pybytes(msg));
    }, py::arg("proof_bytes"), py::arg("public_key"), py::arg("message"));

    zk.def("prove_sufficient_balance", [](uint64_t balance, uint64_t amount,
                                           const py::bytes& bal_blind,
                                           const py::bytes& amt_blind) {
        auto proof = zk::prove_sufficient_balance(
            balance, amount, from_pybytes(bal_blind), from_pybytes(amt_blind));
        return vec_to_pybytes(zk::serialize_balance_proof(proof));
    }, py::arg("balance"), py::arg("amount"),
       py::arg("balance_blinding"), py::arg("amount_blinding"));

    zk.def("verify_sufficient_balance", [](const py::bytes& proof_bytes) {
        std::string_view sv{proof_bytes};
        auto proof = zk::deserialize_balance_proof(
            std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()),
                                 reinterpret_cast<const uint8_t*>(sv.data()) + sv.size()));
        return zk::verify_sufficient_balance(proof);
    }, py::arg("proof_bytes"));

    // ── Utilities ─────────────────────────────────────────────────────────────
    m.def("secure_memequal", [](const py::bytes& a, const py::bytes& b) {
        std::string_view sa{a}, sb{b};
        if (sa.size() != sb.size()) return false;
        return secure_memequal(sa.data(), sb.data(), sa.size());
    }, py::arg("a"), py::arg("b"),
       "Constant-time byte comparison. Returns True if equal.");

    m.attr("VERSION") = "1.0.0";
}
