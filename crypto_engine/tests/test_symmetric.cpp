/**
 * test_symmetric.cpp — Tests for AES-256-GCM, ChaCha20-Poly1305, HKDF.
 */

#include "symmetric.hpp"
#include "secure_memory.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace blackpay::crypto;

void test_aes256gcm() {
    std::cout << "AES-256-GCM: ";
    auto key = AES256GCM::generate_key();
    assert(key.size() == 32);

    const std::string plaintext_str = "BlackPay secret payment data";
    SecureBuffer pt(reinterpret_cast<const uint8_t*>(plaintext_str.data()),
                    plaintext_str.size());

    const std::string aad_str = "transaction-id-12345";
    SecureBuffer aad(reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size());

    auto [ct, nonce] = AES256GCM::encrypt(key, pt, aad);
    assert(!ct.empty());
    assert(nonce.size() == 12);

    auto recovered = AES256GCM::decrypt(key, nonce, ct, aad);
    assert(recovered.size() == pt.size());
    assert(secure_memequal(pt.data(), recovered.data(), pt.size()));
    std::cout << "enc/dec PASS | ";

    // Wrong AAD must fail
    SecureBuffer bad_aad(aad_str.size());
    bool threw = false;
    try {
        AES256GCM::decrypt(key, nonce, ct, bad_aad);
    } catch (...) { threw = true; }
    assert(threw);
    std::cout << "auth PASS\n";
}

void test_chacha20() {
    std::cout << "ChaCha20-Poly1305: ";
    auto key = ChaCha20Poly1305::generate_key();
    assert(key.size() == 32);

    const std::string plaintext_str = "Another secret payload for test";
    SecureBuffer pt(reinterpret_cast<const uint8_t*>(plaintext_str.data()),
                    plaintext_str.size());

    auto [ct, nonce] = ChaCha20Poly1305::encrypt(key, pt);
    auto recovered = ChaCha20Poly1305::decrypt(key, nonce, ct);
    assert(secure_memequal(pt.data(), recovered.data(), pt.size()));
    std::cout << "enc/dec PASS\n";
}

void test_hkdf() {
    std::cout << "HKDF-SHA512: ";
    const std::string ikm_str = "input key material";
    const std::string salt_str = "BlackPay-salt";
    const std::string info_str = "BlackPay-HKDF-test";
    SecureBuffer ikm(reinterpret_cast<const uint8_t*>(ikm_str.data()), ikm_str.size());
    SecureBuffer salt(reinterpret_cast<const uint8_t*>(salt_str.data()), salt_str.size());
    SecureBuffer info(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size());

    auto key1 = HKDF::derive(ikm, salt, info, 32);
    auto key2 = HKDF::derive(ikm, salt, info, 32);
    assert(key1.size() == 32);
    assert(secure_memequal(key1.data(), key2.data(), 32));

    auto key3 = HKDF::derive(ikm, salt, info, 64);
    assert(key3.size() == 64);

    std::cout << "PASS (hex=" << key1.to_hex().substr(0, 16) << "...)\n";
}

int main() {
    std::cout << "=== BlackPay Symmetric Crypto Tests ===\n\n";
    test_aes256gcm();
    test_chacha20();
    test_hkdf();
    std::cout << "\n=== All symmetric tests PASS ===\n";
    return 0;
}
