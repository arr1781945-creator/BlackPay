cmake_minimum_required(VERSION 3.20)
project(blackpay_crypto VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Security flags
add_compile_options(
    -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIC
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
)

add_link_options(
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

# Dependencies
find_package(OpenSSL 3.0 REQUIRED)
find_package(pybind11 REQUIRED)

# liboqs
find_path(OQS_INCLUDE_DIR oqs/oqs.h
    PATHS /usr/local/include /usr/include
    REQUIRED
)
find_library(OQS_LIBRARY oqs
    PATHS /usr/local/lib /usr/lib
    REQUIRED
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

set(CRYPTO_SOURCES
    src/pqc_engine.cpp
    src/symmetric.cpp
    src/hybrid_kem.cpp
    src/zk_engine.cpp
    src/secure_memory.cpp
)

# Static library
add_library(blackpay_crypto_static STATIC ${CRYPTO_SOURCES})
target_link_libraries(blackpay_crypto_static
    ${OQS_LIBRARY}
    OpenSSL::Crypto
    OpenSSL::SSL
)

# pybind11 module
pybind11_add_module(blackpay_crypto bindings/blackpay_crypto.cpp ${CRYPTO_SOURCES})
target_link_libraries(blackpay_crypto PRIVATE
    ${OQS_LIBRARY}
    OpenSSL::Crypto
    OpenSSL::SSL
)
target_compile_definitions(blackpay_crypto PRIVATE VERSION_INFO="1.0.0")

# Tests
enable_testing()

add_executable(test_pqc tests/test_pqc.cpp ${CRYPTO_SOURCES})
target_link_libraries(test_pqc ${OQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)
add_test(NAME test_pqc COMMAND test_pqc)

add_executable(test_hybrid_kem tests/test_hybrid_kem.cpp ${CRYPTO_SOURCES})
target_link_libraries(test_hybrid_kem ${OQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)
add_test(NAME test_hybrid_kem COMMAND test_hybrid_kem)

add_executable(test_symmetric tests/test_symmetric.cpp ${CRYPTO_SOURCES})
target_link_libraries(test_symmetric ${OQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)
add_test(NAME test_symmetric COMMAND test_symmetric)

install(TARGETS blackpay_crypto LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
