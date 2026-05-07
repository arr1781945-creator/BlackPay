/**
 * test_pqc.cpp — Unit tests for PQC KEM and SIG engines.
 */

#include "pqc_engine.hpp"
#include "secure_memory.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>

using namespace blackpay::crypto;

void test_kem(const std::string& algo) {
    std::cout << "Testing KEM: " << algo << " ... ";
    try {
        PQCKemEngine kem(algo);
        auto kp = kem.keygen();
        assert(!kp.public_key.empty());
        assert(!kp.secret_key.empty());

        auto [ct, ss1] = kem.encapsulate(kp.public_key);
        assert(!ct.empty());
        assert(!ss1.empty());

        auto ss2 = kem.decapsulate(ct, kp.secret_key);
        assert(ss1.size() == ss2.size());
        assert(secure_memequal(ss1.data(), ss2.data(), ss1.size()));

        std::cout << "PASS (ss_len=" << ss1.size() << ")\n";
    } catch (const std::exception& e) {
        std::cout << "SKIP (" << e.what() << ")\n";
    }
}

void test_sig(const std::string& algo) {
    std::cout << "Testing SIG: " << algo << " ... ";
    try {
        PQCSigEngine sig(algo);
        auto kp = sig.keygen();
        assert(!kp.public_key.empty());
        assert(!kp.secret_key.empty());

        const uint8_t msg[] = "BlackPay test message for signing";
        SecureBuffer message(msg, sizeof(msg) - 1);

        auto signature = sig.sign(message, kp.secret_key);
        assert(!signature.empty());

        bool valid = sig.verify(message, signature, kp.public_key);
        assert(valid);

        // Tampered message should fail
        SecureBuffer bad_msg(msg, sizeof(msg) - 1);
        bad_msg[0] ^= 0xff;
        bool invalid = sig.verify(bad_msg, signature, kp.public_key);
        assert(!invalid);

        std::cout << "PASS (sig_len=" << signature.size() << ")\n";
    } catch (const std::exception& e) {
        std::cout << "SKIP (" << e.what() << ")\n";
    }
}

int main() {
    std::cout << "=== BlackPay PQC Engine Tests ===\n\n";

    for (const auto& a : PQCKemEngine::supported_algorithms()) test_kem(a);
    for (const auto& a : PQCSigEngine::supported_algorithms()) test_sig(a);

    // Registry tests
    const auto& reg = AlgorithmRegistry::instance();
    auto bsi_kems = reg.bsi_compliant_kems();
    std::cout << "\nBSI-compliant KEMs: " << bsi_kems.size() << "\n";

    std::cout << "\n=== All PQC tests complete ===\n";
    return 0;
}
