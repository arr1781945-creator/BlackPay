"""
apps/crypto_bridge/loader.py
Lazy loader for the blackpay_crypto pybind11 extension module.

Raises ImportError with a helpful message when the .so is absent
(e.g. running tests without a compiled engine).  A stub/mock is used
in that case if BLACKPAY_CRYPTO_STUB=1 is set in the environment.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import ModuleType
from typing import Optional

_engine: Optional[ModuleType] = None


def get_engine() -> ModuleType:
    """
    Return the blackpay_crypto C++ extension module (cached singleton).

    Raises:
        ImportError: if the module is not compiled and no stub is configured.
    """
    global _engine  # noqa: PLW0603
    if _engine is not None:
        return _engine

    # Allow test runs with a stub module
    if os.environ.get("BLACKPAY_CRYPTO_STUB") == "1":
        _engine = _load_stub()
        return _engine

    try:
        _engine = importlib.import_module("blackpay_crypto")
    except ImportError as exc:
        raise ImportError(
            "blackpay_crypto C++ extension not found.  "
            "Build it with: cd crypto_engine/build && cmake .. && make  "
            "Or set BLACKPAY_CRYPTO_STUB=1 for test/CI environments."
        ) from exc

    return _engine


def _load_stub() -> ModuleType:
    """
    Load a minimal stub module for test environments where the C++ engine
    is not compiled.  Operations raise NotImplementedError.
    """
    import types

    stub = types.ModuleType("blackpay_crypto_stub")

    class _StubKEM:
        def __init__(self, alg: str) -> None:
            self.algorithm = alg

        def keygen(self):
            # Return 32-byte zero placeholders for unit tests
            return (b"\x00" * 32, b"\x00" * 32)

        def encapsulate(self, pk: bytes):
            return (b"\x00" * 32, b"\x00" * 32)

        def decapsulate(self, ct: bytes, sk: bytes) -> bytes:
            return b"\x00" * 32

        @staticmethod
        def supported_algorithms() -> list[str]:
            return ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

    class _StubSIG:
        def __init__(self, alg: str) -> None:
            self.algorithm = alg

        def keygen(self):
            return (b"\x00" * 32, b"\x00" * 32)

        def sign(self, msg: bytes, sk: bytes) -> bytes:
            return b"\x00" * 64

        def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
            return True

        @staticmethod
        def supported_algorithms() -> list[str]:
            return ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

    class _StubAES:
        KEY_LEN = 32
        NONCE_LEN = 12
        TAG_LEN = 16

        @staticmethod
        def generate_key() -> bytes:
            return b"\x00" * 32

        @staticmethod
        def generate_nonce() -> bytes:
            return b"\x00" * 12

        @staticmethod
        def encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
            return (plaintext, b"\x00" * 12)

        @staticmethod
        def decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
            return ct

    class _StubHKDF:
        @staticmethod
        def derive(ikm, salt, info, length):
            return b"\x00" * length

        @staticmethod
        def derive_aes_key(ss, info):
            return b"\x00" * 32

    class _StubHybridKEM:
        def __init__(self, label="BlackPay-HybridKEM-v1"):
            self.context_label = label

        def keygen(self):
            return (b"\x00" * 64, b"\x00" * 64)

        def encapsulate(self, pk):
            return (b"\x00" * 64, b"\x00" * 32)

        def decapsulate(self, ct, sk):
            return b"\x00" * 32

    class _StubZK:
        @staticmethod
        def prove_identity(sk, pk, msg):
            return b"\x00" * 96

        @staticmethod
        def verify_identity(proof, pk, msg):
            return True

        @staticmethod
        def prove_sufficient_balance(balance, amount, bb, ab):
            return b"\x00" * 256

        @staticmethod
        def verify_sufficient_balance(proof):
            return True

    stub.PQCKemEngine = _StubKEM
    stub.PQCSigEngine = _StubSIG
    stub.AES256GCM = _StubAES
    stub.HKDF = _StubHKDF
    stub.HybridKEM = _StubHybridKEM
    stub.zk = _StubZK()
    stub.secure_memequal = lambda a, b: a == b
    stub.VERSION = "stub"

    return stub
