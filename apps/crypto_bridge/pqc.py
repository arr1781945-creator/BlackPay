"""
apps/crypto_bridge/pqc.py
Python wrapper around the C++ PQC engine (pybind11 module).

Provides algorithm-agile KEM and digital-signature operations.
All key material is returned as bytes and must be stored encrypted
(see symmetric.py for field-level encryption helpers).

Supported KEM algorithms (liboqs identifiers):
    ML-KEM-512, ML-KEM-768, ML-KEM-1024,
    FrodoKEM-{640,976,1344}-AES, eFrodoKEM-{640,976,1344}-AES,
    BIKE-L{1,2,3}, HQC-{128,192,256},
    Classic-McEliece-{348864,460896,6688128,8192128}

Supported SIG algorithms:
    ML-DSA-{44,65,87}, Falcon-{512,1024},
    SPHINCS+-SHA2-{128,192,256}{f,s}-simple,
    MAYO-{1,2,3,5}, CROSS-rsdp-128-balanced,
    OV-Ip, OV-III, OV-V, SNOVA variants
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Final

from django.conf import settings

from apps.crypto_bridge.exceptions import CryptoError
from apps.crypto_bridge.loader import get_engine

log = logging.getLogger("blackpay.crypto.pqc")

# Default algorithms — overridden per-tenant via PQC config
DEFAULT_KEM: Final[str] = getattr(settings, "PQC_DEFAULT_KEM", "ML-KEM-1024")
DEFAULT_SIG: Final[str] = getattr(settings, "PQC_DEFAULT_SIG", "ML-DSA-65")


# ─── Data classes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class KEMKeyPair:
    """Public / secret key pair for a KEM algorithm."""

    public_key: bytes
    """Raw public key bytes — safe to store and share."""

    secret_key: bytes
    """Raw secret key bytes — must be stored encrypted."""

    algorithm: str
    """liboqs algorithm identifier."""

    def public_b64(self) -> str:
        """Base64-encoded public key (URL-safe, no padding)."""
        return base64.urlsafe_b64encode(self.public_key).decode()

    def secret_b64(self) -> str:
        """Base64-encoded secret key (URL-safe, no padding)."""
        return base64.urlsafe_b64encode(self.secret_key).decode()


@dataclass(frozen=True)
class KEMEncapResult:
    """Result of a KEM encapsulation operation."""

    ciphertext: bytes
    """Ciphertext — send to recipient."""

    shared_secret: bytes
    """Shared secret — use for symmetric key derivation, then discard."""


@dataclass(frozen=True)
class SigKeyPair:
    """Public / secret key pair for a signature algorithm."""

    public_key: bytes
    secret_key: bytes
    algorithm: str


# ─── KEM operations ───────────────────────────────────────────────────────────


def kem_keygen(algorithm: str = DEFAULT_KEM) -> KEMKeyPair:
    """
    Generate a fresh KEM key pair for the given algorithm.

    Args:
        algorithm: liboqs KEM algorithm name (default: settings.PQC_DEFAULT_KEM).

    Returns:
        KEMKeyPair with raw public/secret key bytes.

    Raises:
        CryptoError: if the algorithm is unsupported or keygen fails.
    """
    try:
        engine = get_engine()
        kem = engine.PQCKemEngine(algorithm)
        pk, sk = kem.keygen()
        log.debug("KEM keygen ok", extra={"algorithm": algorithm, "pk_len": len(pk)})
        return KEMKeyPair(public_key=pk, secret_key=sk, algorithm=algorithm)
    except Exception as exc:
        raise CryptoError(f"KEM keygen failed [{algorithm}]: {exc}") from exc


def kem_encapsulate(public_key: bytes, algorithm: str = DEFAULT_KEM) -> KEMEncapResult:
    """
    Encapsulate: generate ciphertext and shared secret for a recipient's public key.

    Args:
        public_key: Recipient's raw KEM public key bytes.
        algorithm:  liboqs KEM algorithm name.

    Returns:
        KEMEncapResult containing ciphertext and shared_secret.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        kem = engine.PQCKemEngine(algorithm)
        ct, ss = kem.encapsulate(public_key)
        return KEMEncapResult(ciphertext=ct, shared_secret=ss)
    except Exception as exc:
        raise CryptoError(f"KEM encapsulate failed [{algorithm}]: {exc}") from exc


def kem_decapsulate(
    ciphertext: bytes,
    secret_key: bytes,
    algorithm: str = DEFAULT_KEM,
) -> bytes:
    """
    Decapsulate: recover shared secret from ciphertext using the secret key.

    Args:
        ciphertext: Ciphertext bytes from encapsulate().
        secret_key: Recipient's raw KEM secret key bytes.
        algorithm:  liboqs KEM algorithm name.

    Returns:
        Shared secret bytes.

    Raises:
        CryptoError: if decapsulation fails (wrong key, tampered ciphertext).
    """
    try:
        engine = get_engine()
        kem = engine.PQCKemEngine(algorithm)
        ss = kem.decapsulate(ciphertext, secret_key)
        return ss
    except Exception as exc:
        raise CryptoError(f"KEM decapsulate failed [{algorithm}]: {exc}") from exc


# ─── Signature operations ─────────────────────────────────────────────────────


def sig_keygen(algorithm: str = DEFAULT_SIG) -> SigKeyPair:
    """
    Generate a fresh signature key pair.

    Args:
        algorithm: liboqs SIG algorithm name (default: settings.PQC_DEFAULT_SIG).

    Returns:
        SigKeyPair with raw public/secret key bytes.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        sig = engine.PQCSigEngine(algorithm)
        pk, sk = sig.keygen()
        log.debug("SIG keygen ok", extra={"algorithm": algorithm})
        return SigKeyPair(public_key=pk, secret_key=sk, algorithm=algorithm)
    except Exception as exc:
        raise CryptoError(f"SIG keygen failed [{algorithm}]: {exc}") from exc


def sig_sign(
    message: bytes,
    secret_key: bytes,
    algorithm: str = DEFAULT_SIG,
) -> bytes:
    """
    Sign a message with a PQC secret key.

    Args:
        message:    Raw bytes to sign.
        secret_key: Raw secret key bytes.
        algorithm:  liboqs SIG algorithm name.

    Returns:
        Signature bytes.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        sig = engine.PQCSigEngine(algorithm)
        return sig.sign(message, secret_key)
    except Exception as exc:
        raise CryptoError(f"SIG sign failed [{algorithm}]: {exc}") from exc


def sig_verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: str = DEFAULT_SIG,
) -> bool:
    """
    Verify a PQC signature. Constant-time at the C++ layer.

    Args:
        message:    Raw bytes that were signed.
        signature:  Signature bytes to verify.
        public_key: Raw public key bytes.
        algorithm:  liboqs SIG algorithm name.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        CryptoError: on unexpected error (not on invalid signature).
    """
    try:
        engine = get_engine()
        sig = engine.PQCSigEngine(algorithm)
        return sig.verify(message, signature, public_key)
    except Exception as exc:
        raise CryptoError(f"SIG verify failed [{algorithm}]: {exc}") from exc


# ─── Algorithm registry helpers ───────────────────────────────────────────────


def supported_kems() -> list[str]:
    """Return all KEM algorithm names supported by the installed liboqs."""
    try:
        return get_engine().PQCKemEngine.supported_algorithms()
    except Exception as exc:
        raise CryptoError(f"supported_kems failed: {exc}") from exc


def supported_sigs() -> list[str]:
    """Return all SIG algorithm names supported by the installed liboqs."""
    try:
        return get_engine().PQCSigEngine.supported_algorithms()
    except Exception as exc:
        raise CryptoError(f"supported_sigs failed: {exc}") from exc
