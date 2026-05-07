"""
apps/crypto_bridge/zk.py
Python wrapper for the C++ Zero-Knowledge proof engine.

Exposes:
  - Schnorr identity proofs (prove knowledge of a secret key)
  - Balance proofs (prove balance >= amount without revealing values)

All proof blobs are opaque bytes — the C++ engine handles serialisation.
Store proofs in the database as base64 strings for readability.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

from apps.crypto_bridge.exceptions import CryptoError
from apps.crypto_bridge.loader import get_engine

log = logging.getLogger("blackpay.crypto.zk")


@dataclass(frozen=True)
class IdentityProof:
    """Serialised Schnorr identity proof."""

    proof_bytes: bytes
    """96 bytes: commitment_r (32) || response_s (32) || challenge_c (32)."""

    def to_b64(self) -> str:
        """Base64url-encoded proof for API / database storage."""
        return base64.urlsafe_b64encode(self.proof_bytes).decode()

    @classmethod
    def from_b64(cls, b64: str) -> "IdentityProof":
        """Reconstruct proof from base64url string."""
        return cls(proof_bytes=base64.urlsafe_b64decode(b64.encode()))


@dataclass(frozen=True)
class BalanceProof:
    """Serialised sufficient-balance ZK proof."""

    proof_bytes: bytes
    """Serialised balance proof from C++ zk_engine."""

    def to_b64(self) -> str:
        return base64.urlsafe_b64encode(self.proof_bytes).decode()

    @classmethod
    def from_b64(cls, b64: str) -> "BalanceProof":
        return cls(proof_bytes=base64.urlsafe_b64decode(b64.encode()))


# ─── Identity proofs ──────────────────────────────────────────────────────────


def prove_identity(
    secret_key: bytes,
    public_key: bytes,
    message: bytes,
) -> IdentityProof:
    """
    Generate a Schnorr proof of knowledge of secret_key for public_key.

    Args:
        secret_key: 32-byte scalar (KEM or signing secret key).
        public_key: Corresponding 32-byte public key / point.
        message:    Binding message — ties proof to a specific context
                    (e.g. transaction ID, challenge nonce).

    Returns:
        IdentityProof containing 96-byte serialised proof.

    Raises:
        CryptoError: on failure.
    """
    try:
        engine = get_engine()
        proof_bytes = engine.zk.prove_identity(secret_key, public_key, message)
        log.debug("ZK identity proof generated", extra={"msg_len": len(message)})
        return IdentityProof(proof_bytes=proof_bytes)
    except Exception as exc:
        raise CryptoError(f"ZK prove_identity failed: {exc}") from exc


def verify_identity(
    proof: IdentityProof,
    public_key: bytes,
    message: bytes,
) -> bool:
    """
    Verify a Schnorr identity proof.

    Args:
        proof:      IdentityProof from prove_identity().
        public_key: Claimed public key.
        message:    Binding message (must match proof generation).

    Returns:
        True if the proof is valid, False otherwise.

    Raises:
        CryptoError: on unexpected engine error.
    """
    try:
        engine = get_engine()
        return engine.zk.verify_identity(proof.proof_bytes, public_key, message)
    except Exception as exc:
        raise CryptoError(f"ZK verify_identity failed: {exc}") from exc


# ─── Balance proofs ───────────────────────────────────────────────────────────


def prove_sufficient_balance(
    balance: int,
    amount: int,
    balance_blinding: bytes,
    amount_blinding: bytes,
) -> BalanceProof:
    """
    Prove balance >= amount without revealing either value.

    Args:
        balance:          Actual wallet balance in base currency units (e.g. satoshis).
        amount:           Payment amount in the same units.
        balance_blinding: 32-byte random blinding factor for balance commitment.
        amount_blinding:  32-byte random blinding factor for amount commitment.

    Returns:
        BalanceProof containing serialised proof bytes.

    Raises:
        CryptoError: if balance < amount or on engine failure.
    """
    if balance < amount:
        raise CryptoError(
            f"Cannot prove balance ({balance}) >= amount ({amount}): insufficient funds"
        )
    if len(balance_blinding) != 32 or len(amount_blinding) != 32:
        raise CryptoError("Blinding factors must be exactly 32 bytes each")
    try:
        engine = get_engine()
        proof_bytes = engine.zk.prove_sufficient_balance(
            balance, amount, balance_blinding, amount_blinding
        )
        log.debug(
            "ZK balance proof generated",
            extra={"balance": balance, "amount": amount},
        )
        return BalanceProof(proof_bytes=proof_bytes)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"ZK prove_sufficient_balance failed: {exc}") from exc


def verify_sufficient_balance(proof: BalanceProof) -> bool:
    """
    Verify a sufficient-balance ZK proof.

    Args:
        proof: BalanceProof from prove_sufficient_balance().

    Returns:
        True if the proof is valid.

    Raises:
        CryptoError: on engine error.
    """
    try:
        engine = get_engine()
        return engine.zk.verify_sufficient_balance(proof.proof_bytes)
    except Exception as exc:
        raise CryptoError(f"ZK verify_sufficient_balance failed: {exc}") from exc


# ─── Utility ──────────────────────────────────────────────────────────────────


def generate_blinding_factor() -> bytes:
    """
    Generate a cryptographically random 32-byte blinding factor.

    Used as input to prove_sufficient_balance(). Must be stored
    encrypted alongside the commitment for future proof generation.

    Returns:
        32 random bytes.
    """
    import os

    return os.urandom(32)


def secure_memequal(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison via C++ engine.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if a == b (same length and content), in constant time.
    """
    try:
        engine = get_engine()
        return engine.secure_memequal(a, b)
    except Exception as exc:
        raise CryptoError(f"secure_memequal failed: {exc}") from exc
