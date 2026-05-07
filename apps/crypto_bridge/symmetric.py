"""
apps/crypto_bridge/symmetric.py
Python wrappers for AES-256-GCM, ChaCha20-Poly1305, and HKDF-SHA512.

These helpers are used for:
  - Field-level encryption of sensitive database columns
  - Session key derivation from KEM shared secrets
  - Envelope encryption of private keys at rest

All serialised blobs use the format:
    <nonce (12 bytes)> || <ciphertext_with_tag>

This is compact and self-contained — the nonce is unique per encryption.
"""

from __future__ import annotations

import base64
import logging
import struct
from dataclasses import dataclass
from typing import Final

from apps.crypto_bridge.exceptions import CryptoError
from apps.crypto_bridge.loader import get_engine

log = logging.getLogger("blackpay.crypto.symmetric")

NONCE_LEN: Final[int] = 12  # AES-GCM / ChaCha20-Poly1305 nonce
TAG_LEN: Final[int] = 16    # AEAD authentication tag


# ─── Serialisation ────────────────────────────────────────────────────────────


def _pack(nonce: bytes, ciphertext: bytes) -> bytes:
    """Pack nonce + ciphertext into a single blob: [nonce][ciphertext]."""
    if len(nonce) != NONCE_LEN:
        raise CryptoError(f"Invalid nonce length: {len(nonce)}")
    return nonce + ciphertext


def _unpack(blob: bytes) -> tuple[bytes, bytes]:
    """Unpack blob into (nonce, ciphertext). Raises CryptoError on bad format."""
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise CryptoError(
            f"Encrypted blob too short: {len(blob)} bytes (min {NONCE_LEN + TAG_LEN})"
        )
    return blob[:NONCE_LEN], blob[NONCE_LEN:]


# ─── AES-256-GCM ──────────────────────────────────────────────────────────────


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        key:       32-byte symmetric key.
        plaintext: Data to encrypt (may be empty).
        aad:       Additional authenticated data — authenticated but not encrypted.
                   Use for binding context (e.g. user ID, record UUID).

    Returns:
        Compact blob: nonce (12 bytes) || ciphertext || tag (16 bytes).

    Raises:
        CryptoError: if key length is wrong or encryption fails.
    """
    if len(key) != 32:
        raise CryptoError(f"AES-256-GCM key must be 32 bytes, got {len(key)}")
    try:
        engine = get_engine()
        ct, nonce = engine.AES256GCM.encrypt(key, plaintext, aad)
        return _pack(nonce, ct)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"AES encrypt failed: {exc}") from exc


def aes_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt an AES-256-GCM blob produced by aes_encrypt().

    Args:
        key:  32-byte symmetric key.
        blob: Blob from aes_encrypt() (nonce || ciphertext || tag).
        aad:  Must match the aad used during encryption.

    Returns:
        Plaintext bytes.

    Raises:
        CryptoError: if authentication fails or decryption errors.
    """
    if len(key) != 32:
        raise CryptoError(f"AES-256-GCM key must be 32 bytes, got {len(key)}")
    try:
        nonce, ct = _unpack(blob)
        engine = get_engine()
        return engine.AES256GCM.decrypt(key, nonce, ct, aad)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"AES decrypt failed: {exc}") from exc


def aes_generate_key() -> bytes:
    """
    Generate a cryptographically random 32-byte AES-256 key.

    Returns:
        32 random bytes from the OS CSPRNG.
    """
    try:
        return get_engine().AES256GCM.generate_key()
    except Exception as exc:
        raise CryptoError(f"AES key generation failed: {exc}") from exc


# ─── ChaCha20-Poly1305 ────────────────────────────────────────────────────────


def chacha_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt plaintext with ChaCha20-Poly1305 (RFC 8439).

    Args:
        key:       32-byte key.
        plaintext: Data to encrypt.
        aad:       Additional authenticated data.

    Returns:
        Compact blob: nonce (12 bytes) || ciphertext || tag (16 bytes).

    Raises:
        CryptoError: on failure.
    """
    if len(key) != 32:
        raise CryptoError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    try:
        engine = get_engine()
        ct, nonce = engine.ChaCha20Poly1305.encrypt(key, plaintext, aad)
        return _pack(nonce, ct)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"ChaCha20 encrypt failed: {exc}") from exc


def chacha_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt a ChaCha20-Poly1305 blob produced by chacha_encrypt().

    Raises:
        CryptoError: if authentication fails.
    """
    if len(key) != 32:
        raise CryptoError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    try:
        nonce, ct = _unpack(blob)
        engine = get_engine()
        return engine.ChaCha20Poly1305.decrypt(key, nonce, ct, aad)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"ChaCha20 decrypt failed: {exc}") from exc


# ─── HKDF-SHA512 ──────────────────────────────────────────────────────────────


def hkdf_derive(
    ikm: bytes,
    info: bytes,
    length: int = 32,
    salt: bytes = b"",
) -> bytes:
    """
    Derive a key of `length` bytes using HKDF-SHA512.

    Args:
        ikm:    Input key material (e.g. KEM shared secret).
        info:   Context / application string for domain separation.
        length: Output length in bytes (1–8160).
        salt:   Optional salt; defaults to empty (HKDF uses HashLen zeros).

    Returns:
        Derived key bytes.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        return engine.HKDF.derive(ikm, salt, info, length)
    except Exception as exc:
        raise CryptoError(f"HKDF derive failed: {exc}") from exc


def hkdf_derive_aes_key(shared_secret: bytes, info: bytes) -> bytes:
    """
    Convenience: derive a 32-byte AES-256 key from a KEM shared secret.

    Args:
        shared_secret: Raw bytes from KEM decapsulation.
        info:          Domain-separation label (e.g. b"BlackPay-field-encryption-v1").

    Returns:
        32-byte AES key.
    """
    try:
        engine = get_engine()
        return engine.HKDF.derive_aes_key(shared_secret, info)
    except Exception as exc:
        raise CryptoError(f"HKDF AES key derive failed: {exc}") from exc


# ─── Field-level encryption helpers ──────────────────────────────────────────


def encrypt_field(plaintext: str, key: bytes, aad: bytes = b"") -> str:
    """
    Encrypt a string field for database storage.

    Args:
        plaintext: UTF-8 string to encrypt.
        key:       32-byte AES key (from FIELD_ENCRYPTION_KEY setting).
        aad:       Binding context (e.g. model name + record UUID as bytes).

    Returns:
        Base64url-encoded encrypted blob (safe for text columns).
    """
    raw = aes_encrypt(key, plaintext.encode("utf-8"), aad)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decrypt_field(encrypted: str, key: bytes, aad: bytes = b"") -> str:
    """
    Decrypt a string field previously encrypted by encrypt_field().

    Args:
        encrypted: Base64url-encoded blob from encrypt_field().
        key:       32-byte AES key.
        aad:       Must match the aad used during encryption.

    Returns:
        Original plaintext string.

    Raises:
        CryptoError: if decryption or authentication fails.
    """
    raw = base64.urlsafe_b64decode(encrypted.encode("ascii"))
    return aes_decrypt(key, raw, aad).decode("utf-8")


def get_field_encryption_key() -> bytes:
    """
    Retrieve the platform-level field encryption key from settings.

    The key is stored as a hex string in FIELD_ENCRYPTION_KEY setting.
    In production, this should come from an HSM or secret manager, not .env.

    Raises:
        CryptoError: if the key is missing or malformed.
    """
    from django.conf import settings

    key_hex: str = getattr(settings, "FIELD_ENCRYPTION_KEY", "")
    if not key_hex:
        raise CryptoError(
            "FIELD_ENCRYPTION_KEY is not configured. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise CryptoError(f"FIELD_ENCRYPTION_KEY is not valid hex: {exc}") from exc
    if len(key) != 32:
        raise CryptoError(
            f"FIELD_ENCRYPTION_KEY must be 64 hex chars (32 bytes), "
            f"got {len(key)} bytes"
        )
    return key
