/**
 * secure_memory.cpp
 * Secure memory allocation and zeroization primitives.
 */

#include "secure_memory.hpp"
#include <openssl/crypto.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <new>

namespace blackpay::crypto {

// ─── secure_zero ──────────────────────────────────────────────────────────────

void secure_zero(void* ptr, std::size_t len) noexcept {
    // OPENSSL_cleanse uses platform-specific mechanisms to prevent
    // the compiler from optimising away the zeroing.
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

// ─── secure_memequal ──────────────────────────────────────────────────────────

bool secure_memequal(const void* a, const void* b, std::size_t len) noexcept {
    if (!a || !b) return (a == b) && (len == 0);
    // CRYPTO_memcmp is constant-time
    return CRYPTO_memcmp(a, b, len) == 0;
}

// ─── SecureBuffer ─────────────────────────────────────────────────────────────

SecureBuffer::SecureBuffer(std::size_t size) : size_(size) {
    if (size == 0) { data_ = nullptr; return; }
    data_ = static_cast<uint8_t*>(OPENSSL_secure_malloc(size));
    if (!data_) {
        // Fallback to regular malloc if secure heap not initialised
        data_ = static_cast<uint8_t*>(::operator new(size));
    }
    std::memset(data_, 0, size);
}

SecureBuffer::SecureBuffer(const uint8_t* data, std::size_t size) : size_(size) {
    if (size == 0 || !data) { data_ = nullptr; size_ = 0; return; }
    data_ = static_cast<uint8_t*>(OPENSSL_secure_malloc(size));
    if (!data_) {
        data_ = static_cast<uint8_t*>(::operator new(size));
    }
    std::memcpy(data_, data, size);
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        zeroize();
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

SecureBuffer::~SecureBuffer() {
    zeroize();
}

void SecureBuffer::zeroize() noexcept {
    if (data_) {
        secure_zero(data_, size_);
        if (OPENSSL_secure_allocated(data_)) {
            OPENSSL_secure_free(data_);
        } else {
            ::operator delete(data_);
        }
        data_ = nullptr;
        size_ = 0;
    }
}

std::vector<uint8_t> SecureBuffer::to_vec() const {
    if (!data_ || size_ == 0) return {};
    return std::vector<uint8_t>(data_, data_ + size_);
}

std::string SecureBuffer::to_hex() const {
    std::ostringstream oss;
    for (std::size_t i = 0; i < size_; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(data_[i]);
    }
    return oss.str();
}

SecureBuffer SecureBuffer::from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex string has odd length");
    }
    std::size_t len = hex.size() / 2;
    SecureBuffer buf(len);
    for (std::size_t i = 0; i < len; ++i) {
        unsigned byte = 0;
        std::istringstream ss(hex.substr(i * 2, 2));
        ss >> std::hex >> byte;
        buf[i] = static_cast<uint8_t>(byte);
    }
    return buf;
}

// ─── SecureAllocator ──────────────────────────────────────────────────────────

template<typename T>
T* SecureAllocator<T>::allocate(std::size_t n) {
    if (n == 0) return nullptr;
    std::size_t bytes = n * sizeof(T);
    T* p = static_cast<T*>(OPENSSL_secure_malloc(bytes));
    if (!p) {
        p = static_cast<T*>(::operator new(bytes));
    }
    return p;
}

template<typename T>
void SecureAllocator<T>::deallocate(T* p, std::size_t n) noexcept {
    if (!p) return;
    secure_zero(p, n * sizeof(T));
    if (OPENSSL_secure_allocated(p)) {
        OPENSSL_secure_free(p);
    } else {
        ::operator delete(p);
    }
}

// Explicit instantiations
template struct SecureAllocator<char>;
template struct SecureAllocator<uint8_t>;

} // namespace blackpay::crypto
