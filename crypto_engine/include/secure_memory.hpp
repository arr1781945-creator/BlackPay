#pragma once
/**
 * secure_memory.hpp
 * Provides secure memory allocation, zeroization, and RAII wrappers.
 * All sensitive key material must use SecureBuffer to ensure zeroization.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <string>

namespace blackpay::crypto {

/**
 * Constant-time memory comparison — prevents timing side-channels.
 * Returns true if a and b are identical.
 */
bool secure_memequal(const void* a, const void* b, std::size_t len) noexcept;

/**
 * Zeroize memory in a way the compiler cannot optimize away.
 */
void secure_zero(void* ptr, std::size_t len) noexcept;

/**
 * RAII secure buffer. Memory is zeroized on destruction.
 * Use for all key material, shared secrets, plaintexts.
 */
class SecureBuffer {
public:
    explicit SecureBuffer(std::size_t size);
    SecureBuffer(const uint8_t* data, std::size_t size);
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&&) noexcept;
    SecureBuffer& operator=(SecureBuffer&&) noexcept;
    ~SecureBuffer();

    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    uint8_t& operator[](std::size_t i) noexcept { return data_[i]; }
    const uint8_t& operator[](std::size_t i) const noexcept { return data_[i]; }

    std::vector<uint8_t> to_vec() const;
    std::string to_hex() const;

    static SecureBuffer from_hex(const std::string& hex);

private:
    uint8_t* data_{nullptr};
    std::size_t size_{0};
    void zeroize() noexcept;
};

/**
 * Secure allocator for STL containers.
 * Zeroizes memory on deallocation.
 */
template<typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() = default;
    template<typename U>
    explicit SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n);
    void deallocate(T* p, std::size_t n) noexcept;

    template<typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }
    template<typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using SecureVec    = std::vector<uint8_t, SecureAllocator<uint8_t>>;

} // namespace blackpay::crypto
