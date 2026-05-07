/**
 * test_hybrid_kem.cpp — Tests for X25519 + ML-KEM-1024 hybrid KEM.
 */

#include "hybrid_kem.hpp"
#include "secure_memory.hpp"
#include <cassert>
#include <iostream>

using namespace blackpay::crypto;

int main() {
    std::cout << "=== BlackPay Hybrid KEM Tests ===\n\n";

    HybridKEM kem("BlackPay-test");

    // Keygen
    auto kp = kem.keygen();
    assert(!kp.public_key.x25519_pk.empty());
    assert(!kp.public_key.mlkem_pk.empty());
    assert(!kp.secret_key.x25519_sk.empty());
    assert(!kp.secret_key.mlkem_sk.empty());
    std::cout << "keygen: PASS\n";

    // Serialization round-trip
    auto pub_bytes = kp.public_key.serialize();
    auto pub2 = HybridPublicKey::deserialize(pub_bytes);
    assert(secure_memequal(kp.public_key.x25519_pk.data(),
                           pub2.x25519_pk.data(), 32));
    std::cout << "pub serialization: PASS\n";

    // Encapsulate / decapsulate
    auto [ct, ss1] = kem.encapsulate(kp.public_key);
    assert(ss1.size() == 32);
    std::cout << "encapsulate: PASS (ss=" << ss1.to_hex() << ")\n";

    auto ct_bytes = ct.serialize();
    auto ct2 = HybridCiphertext::deserialize(ct_bytes);

    auto ss2 = kem.decapsulate(ct2, kp.secret_key);
    assert(ss2.size() == 32);
    assert(secure_memequal(ss1.data(), ss2.data(), 32));
    std::cout << "decapsulate: PASS\n";

    // Different keypair should give different secret
    auto kp2 = kem.keygen();
    auto ss3 = kem.decapsulate(ct2, kp2.secret_key);
    assert(!secure_memequal(ss1.data(), ss3.data(), 32));
    std::cout << "wrong key gives different ss: PASS\n";

    std::cout << "\n=== Hybrid KEM tests complete ===\n";
    return 0;
}
