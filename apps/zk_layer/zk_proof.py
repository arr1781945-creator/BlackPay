"""
apps/zk_layer/zk_proof.py
Zero-Knowledge proof orchestration for BlackPay payments.

Provides high-level helpers that the payments and wallet layers call to:
  1. Generate a ZK sufficient-balance proof before authorising a payment.
  2. Generate an identity proof for privileged operations.
  3. Verify proofs received from external parties.

All cryptographic operations are delegated to the C++ engine via
apps.crypto_bridge.zk.  This module handles:
  - Loading/persisting blinding factors (encrypted per-user in the DB)
  - Converting Decimal amounts to integer units for the C++ engine
  - Caching recently-verified proofs to avoid redundant C++ calls
"""

from __future__ import annotations

import logging
import os
from decimal import Decimal
from typing import Optional

from django.core.cache import cache

from apps.crypto_bridge.exceptions import CryptoError
from apps.crypto_bridge.zk import (
    BalanceProof,
    IdentityProof,
    generate_blinding_factor,
    prove_identity,
    prove_sufficient_balance,
    verify_identity,
    verify_sufficient_balance,
)

log = logging.getLogger("blackpay.zk_layer")

# Scale factor: store balances as integer satoshi-equivalents (1e8)
# This avoids Decimal precision issues at the C++ boundary.
AMOUNT_SCALE = 10 ** 8

# Cache TTL for verified proofs (avoid re-verifying within same request burst)
PROOF_CACHE_TTL = 60  # seconds


# ─── Blinding factor storage ──────────────────────────────────────────────────


def _get_or_create_blinding(user_id: str, currency: str, purpose: str) -> bytes:
    """
    Retrieve the user's stored blinding factor for a given currency/purpose,
    or generate and persist a fresh one.

    Blinding factors are stored AES-256-GCM encrypted in the user's wallet record.
    They are needed to re-generate proofs for the same commitment.

    Args:
        user_id:  User UUID string.
        currency: ISO currency code (e.g. "BTC").
        purpose:  Proof purpose label: "balance" or "amount".

    Returns:
        32-byte blinding factor.
    """
    from apps.crypto_bridge.symmetric import decrypt_field, encrypt_field, get_field_encryption_key
    from apps.wallet.models import Wallet

    fek = get_field_encryption_key()
    cache_key = f"blind:{user_id}:{currency}:{purpose}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    try:
        wallet = Wallet.objects.get(user_id=user_id)
    except Wallet.DoesNotExist:
        # Return a fresh ephemeral factor if no wallet yet
        return generate_blinding_factor()

    # Store blinding factors in wallet.metadata under 'zk_blindings'
    # Each entry is an AES-GCM encrypted hex string.
    meta = getattr(wallet, "metadata", {}) or {}
    blindings = meta.get("zk_blindings", {})
    key = f"{currency}_{purpose}"

    if key in blindings:
        try:
            aad = f"{user_id}:{currency}:{purpose}".encode()
            bf_hex = decrypt_field(blindings[key], fek, aad)
            bf = bytes.fromhex(bf_hex)
            cache.set(cache_key, bf, timeout=300)
            return bf
        except Exception as exc:
            log.warning("Blinding factor decrypt failed, generating new", exc_info=exc)

    # Generate fresh blinding factor
    bf = generate_blinding_factor()
    aad = f"{user_id}:{currency}:{purpose}".encode()
    blindings[key] = encrypt_field(bf.hex(), fek, aad)
    meta["zk_blindings"] = blindings

    # Persist if Wallet has a metadata field; otherwise skip persistence
    if hasattr(wallet, "metadata"):
        wallet.metadata = meta
        wallet.save(update_fields=["metadata"])
    else:
        # Add metadata field dynamically (requires migration to persist)
        pass

    cache.set(cache_key, bf, timeout=300)
    return bf


# ─── Balance proof ────────────────────────────────────────────────────────────


def generate_balance_proof(
    user,
    amount: Decimal,
    currency: str,
) -> str:
    """
    Generate a ZK sufficient-balance proof for a payment amount.

    Proves wallet_balance >= payment_amount without revealing either value.
    The proof is serialised to base64 for storage in the Transaction record.

    Args:
        user:     User making the payment.
        amount:   Payment amount as Decimal.
        currency: ISO currency code.

    Returns:
        Base64-encoded BalanceProof string, or empty string on failure.

    Raises:
        CryptoError: if the balance is provably insufficient.
    """
    from apps.wallet.models import Balance, Wallet

    try:
        wallet = Wallet.objects.get(user=user)
        balance_record = Balance.objects.get(wallet=wallet, currency=currency)
        balance_decimal = balance_record.available_amount
    except Exception as exc:
        log.warning("ZK balance proof: wallet lookup failed", exc_info=exc)
        raise CryptoError(f"Could not retrieve balance for {currency}: {exc}") from exc

    # Convert to integer units
    balance_int = int(balance_decimal * AMOUNT_SCALE)
    amount_int = int(amount * AMOUNT_SCALE)

    if balance_int < amount_int:
        raise CryptoError(
            f"Insufficient balance: {balance_decimal} {currency} < {amount} {currency}"
        )

    user_id = str(user.id)
    balance_blind = _get_or_create_blinding(user_id, currency, "balance")
    amount_blind = _get_or_create_blinding(user_id, currency, "amount")

    try:
        proof = prove_sufficient_balance(
            balance=balance_int,
            amount=amount_int,
            balance_blinding=balance_blind,
            amount_blinding=amount_blind,
        )
        log.debug(
            "ZK balance proof generated",
            extra={"user_id": user_id, "currency": currency},
        )
        return proof.to_b64()
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"ZK balance proof generation failed: {exc}") from exc


def verify_balance_proof(proof_b64: str) -> bool:
    """
    Verify a ZK sufficient-balance proof.

    Results are cached for PROOF_CACHE_TTL seconds to avoid redundant
    C++ calls within the same request burst.

    Args:
        proof_b64: Base64-encoded BalanceProof string from generate_balance_proof().

    Returns:
        True if the proof is valid.

    Raises:
        CryptoError: on engine error.
    """
    if not proof_b64:
        return False

    cache_key = f"zk_balance_proof:{hash(proof_b64)}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        proof = BalanceProof.from_b64(proof_b64)
        result = verify_sufficient_balance(proof)
        cache.set(cache_key, result, timeout=PROOF_CACHE_TTL)
        return result
    except Exception as exc:
        raise CryptoError(f"ZK balance proof verification failed: {exc}") from exc


# ─── Identity proof ───────────────────────────────────────────────────────────


def generate_identity_proof(
    user,
    message: bytes,
    key_purpose: str = "mfa",
) -> str:
    """
    Generate a Schnorr identity proof for a user.

    Proves knowledge of the ML-DSA secret key corresponding to a stored
    public key, bound to a specific message (e.g. a transaction challenge).

    Args:
        user:        User generating the proof.
        message:     Binding message bytes (e.g. challenge nonce + tx ID).
        key_purpose: PQCKey purpose to use (default: "mfa").

    Returns:
        Base64-encoded IdentityProof string.

    Raises:
        CryptoError: if no suitable key is found or proof generation fails.
    """
    from apps.users.models import PQCKey

    try:
        pqc_key = PQCKey.objects.get(
            user=user,
            key_type="sig",
            purpose=key_purpose,
            is_active=True,
        )
    except PQCKey.DoesNotExist:
        raise CryptoError(
            f"No active PQC signing key with purpose='{key_purpose}' found for user {user.id}"
        )
    except PQCKey.MultipleObjectsReturned:
        pqc_key = PQCKey.objects.filter(
            user=user, key_type="sig", purpose=key_purpose, is_active=True
        ).order_by("-created_at").first()

    try:
        sk_bytes = pqc_key.get_secret_key_bytes()
        pk_bytes = pqc_key.get_public_key_bytes()

        proof = prove_identity(
            secret_key=sk_bytes,
            public_key=pk_bytes,
            message=message,
        )
        log.debug(
            "ZK identity proof generated",
            extra={"user_id": str(user.id), "key_id": str(pqc_key.id)},
        )
        return proof.to_b64()
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"ZK identity proof generation failed: {exc}") from exc


def verify_identity_proof(
    proof_b64: str,
    public_key_hex: str,
    message: bytes,
) -> bool:
    """
    Verify a Schnorr identity proof.

    Args:
        proof_b64:       Base64-encoded IdentityProof string.
        public_key_hex:  Hex-encoded public key to verify against.
        message:         Binding message (must match proof generation).

    Returns:
        True if valid.

    Raises:
        CryptoError: on engine error.
    """
    if not proof_b64 or not public_key_hex:
        return False

    try:
        proof = IdentityProof.from_b64(proof_b64)
        pk_bytes = bytes.fromhex(public_key_hex)
        result = verify_identity(proof, pk_bytes, message)
        log.debug("ZK identity proof verified", extra={"result": result})
        return result
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"ZK identity proof verification failed: {exc}") from exc


# ─── Transaction signing ──────────────────────────────────────────────────────


def sign_transaction(user, transaction_id: str, amount: Decimal, currency: str) -> str:
    """
    Sign a payment transaction with the user's PQC signing key (ML-DSA-65).

    The signed payload is:
        SHA-256(transaction_id || amount_str || currency || timestamp)

    Args:
        user:           User authorising the transaction.
        transaction_id: Transaction UUID string.
        amount:         Payment amount.
        currency:       Currency code.

    Returns:
        Hex-encoded ML-DSA signature string.

    Raises:
        CryptoError: if signing fails.
    """
    import hashlib
    from django.utils import timezone
    from apps.crypto_bridge.pqc import sig_sign
    from apps.users.models import PQCKey

    try:
        pqc_key = PQCKey.objects.get(
            user=user, key_type="sig", purpose="signing", is_active=True
        )
    except PQCKey.DoesNotExist:
        # Fall back to MFA key for signing if no dedicated signing key
        try:
            pqc_key = PQCKey.objects.get(
                user=user, key_type="sig", purpose="mfa", is_active=True
            )
        except PQCKey.DoesNotExist:
            raise CryptoError(f"No active signing key found for user {user.id}")

    payload = (
        f"{transaction_id}|{amount}|{currency}|{timezone.now().isoformat()}"
    ).encode("utf-8")
    digest = hashlib.sha256(payload).digest()

    try:
        sk_bytes = pqc_key.get_secret_key_bytes()
        signature = sig_sign(digest, sk_bytes, pqc_key.algorithm)
        log.info(
            "Transaction signed",
            extra={"user_id": str(user.id), "tx_id": transaction_id},
        )
        return signature.hex()
    except Exception as exc:
        raise CryptoError(f"Transaction signing failed: {exc}") from exc
