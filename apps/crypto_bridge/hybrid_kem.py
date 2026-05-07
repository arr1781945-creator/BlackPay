"""
apps/crypto_bridge/hybrid_kem.py
Python wrapper for the X25519 + ML-KEM-1024 hybrid KEM.

BSI TR-02102-1 compliant hybrid construction:
    combined_ss = HKDF-SHA512(X25519_ss || ML-KEM-1024_ss, salt=label, L=32)

Usage (key exchange between two BlackPay nodes):

    # Recipient generates a long-term keypair
    pk_bytes, sk_bytes = hybrid_keygen()

    # Sender encapsulates to the recipient's public key
    ciphertext, shared_secret = hybrid_encapsulate(pk_bytes)

    # Recipient decapsulates
    same_secret = hybrid_decapsulate(ciphertext, sk_bytes)

    assert shared_secret == same_secret  # always true

The 32-byte shared_secret is then used as input to HKDF for deriving
symmetric keys via hkdf_derive_aes_key().
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Final

from django.conf import settings

from apps.crypto_bridge.exceptions import CryptoError
from apps.crypto_bridge.loader import get_engine

log = logging.getLogger("blackpay.crypto.hybrid_kem")

DEFAULT_CONTEXT: Final[str] = "BlackPay-HybridKEM-v1"


@dataclass(frozen=True)
class HybridKeyPair:
    """Serialised hybrid keypair (opaque bytes from C++ engine)."""

    public_key: bytes
    """Serialised hybrid public key: [u32 x25519_len][x25519_pk][u32 mlkem_len][mlkem_pk]."""

    secret_key: bytes
    """Serialised hybrid secret key. Must be stored encrypted."""

    context_label: str
    """KEM context label — must match for encap/decap."""

    def public_b64(self) -> str:
        """URL-safe base64 encoded public key."""
        return base64.urlsafe_b64encode(self.public_key).decode()

    def secret_b64(self) -> str:
        """URL-safe base64 encoded secret key."""
        return base64.urlsafe_b64encode(self.secret_key).decode()


@dataclass(frozen=True)
class HybridEncapResult:
    """Result of hybrid KEM encapsulation."""

    ciphertext: bytes
    """Serialised hybrid ciphertext — send to recipient."""

    shared_secret: bytes
    """32-byte combined shared secret. Use for key derivation, then discard."""


def hybrid_keygen(context_label: str = DEFAULT_CONTEXT) -> HybridKeyPair:
    """
    Generate an X25519 + ML-KEM-1024 hybrid keypair.

    Args:
        context_label: Domain-separation label, must match during encap/decap.
                       Use per-tenant labels for tenant isolation.

    Returns:
        HybridKeyPair with serialised public and secret key bytes.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        kem = engine.HybridKEM(context_label)
        pk, sk = kem.keygen()
        log.debug(
            "Hybrid KEM keygen ok",
            extra={"label": context_label, "pk_len": len(pk)},
        )
        return HybridKeyPair(public_key=pk, secret_key=sk, context_label=context_label)
    except Exception as exc:
        raise CryptoError(f"Hybrid KEM keygen failed: {exc}") from exc


def hybrid_encapsulate(
    public_key: bytes,
    context_label: str = DEFAULT_CONTEXT,
) -> HybridEncapResult:
    """
    Encapsulate: generate ciphertext + 32-byte shared secret for a recipient.

    Args:
        public_key:    Serialised hybrid public key bytes (from hybrid_keygen()).
        context_label: Must match the label used during keygen.

    Returns:
        HybridEncapResult with ciphertext and shared_secret.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        kem = engine.HybridKEM(context_label)
        ct, ss = kem.encapsulate(public_key)
        log.debug(
            "Hybrid KEM encapsulate ok",
            extra={"label": context_label, "ct_len": len(ct)},
        )
        return HybridEncapResult(ciphertext=ct, shared_secret=ss)
    except Exception as exc:
        raise CryptoError(f"Hybrid KEM encapsulate failed: {exc}") from exc


def hybrid_decapsulate(
    ciphertext: bytes,
    secret_key: bytes,
    context_label: str = DEFAULT_CONTEXT,
) -> bytes:
    """
    Decapsulate: recover the 32-byte shared secret from ciphertext.

    Args:
        ciphertext:    Serialised hybrid ciphertext from hybrid_encapsulate().
        secret_key:    Serialised hybrid secret key bytes.
        context_label: Must match the label used during keygen and encapsulate.

    Returns:
        32-byte shared secret (identical to the one from encapsulate()).

    Raises:
        CryptoError: on failure (wrong key, tampered ciphertext, label mismatch).
    """
    try:
        engine = get_engine()
        kem = engine.HybridKEM(context_label)
        ss = kem.decapsulate(ciphertext, secret_key)
        return ss
    except Exception as exc:
        raise CryptoError(f"Hybrid KEM decapsulate failed: {exc}") from exc


def hybrid_derive_session_key(
    public_key: bytes,
    context_label: str = DEFAULT_CONTEXT,
    hkdf_info: bytes = b"BlackPay-session-key-v1",
) -> tuple[bytes, bytes]:
    """
    Convenience: encapsulate and immediately derive a 32-byte AES session key.

    Args:
        public_key:    Recipient's hybrid public key.
        context_label: KEM context label.
        hkdf_info:     HKDF domain-separation info for the derived key.

    Returns:
        Tuple of (ciphertext_bytes, derived_aes_key_32_bytes).
        The ciphertext must be transmitted to the recipient.
    """
    from apps.crypto_bridge.symmetric import hkdf_derive_aes_key

    result = hybrid_encapsulate(public_key, context_label)
    aes_key = hkdf_derive_aes_key(result.shared_secret, hkdf_info)
    return result.ciphertext, aes_key
