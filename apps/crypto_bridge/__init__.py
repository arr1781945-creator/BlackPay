"""
apps/crypto_bridge
Python bridge to the BlackPay C++ pybind11 crypto engine (blackpay_crypto.so).

Sub-modules:
  pqc        — KEM and signature operations (ML-KEM, ML-DSA, Falcon, …)
  symmetric  — AES-256-GCM, ChaCha20-Poly1305, HKDF
  hybrid_kem — X25519 + ML-KEM-1024 hybrid KEM
  zk         — Zero-Knowledge proof helpers

All functions in this package operate on plain Python bytes / str and raise
CryptoError on failure.  Callers should never import blackpay_crypto directly.
"""

from apps.crypto_bridge.exceptions import CryptoError  # noqa: F401

__all__ = ["CryptoError"]
