"""
apps/users/pqc_auth.py
PQC-based authentication helpers.

Implements the BlackPay PQC-MFA flow:
  1. After password auth, server creates an MFASession with a random challenge.
  2. Client retrieves the challenge and signs it with their ML-DSA secret key.
  3. Server verifies the signature against the stored ML-DSA public key.
  4. On success, JWT access + refresh tokens are issued.

Also provides helpers for:
  - Generating and persisting PQC key pairs for new users
  - Signing audit log entries with the platform signing key
  - Verifying request signatures for privileged operations
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import timedelta
from typing import Optional

from django.conf import settings
from django.utils import timezone

from apps.crypto_bridge.exceptions import CryptoError
from apps.crypto_bridge.pqc import sig_keygen, sig_sign, sig_verify
from apps.crypto_bridge.symmetric import (
    decrypt_field,
    encrypt_field,
    get_field_encryption_key,
)
from apps.users.models import AuditLog, MFASession, PQCKey, User

log = logging.getLogger("blackpay.users.pqc_auth")

# MFA session lifetime
MFA_SESSION_TTL_SECONDS = 300  # 5 minutes


# ─── Key management ──────────────────────────────────────────────────────────


def generate_user_pqc_keypair(
    user: User,
    key_type: str = "sig",
    purpose: str = "mfa",
    algorithm: Optional[str] = None,
) -> PQCKey:
    """
    Generate a PQC key pair for a user and persist it to the database.

    The secret key is encrypted with the platform FIELD_ENCRYPTION_KEY
    before storage. The public key is stored in plaintext hex.

    Args:
        user:      User instance to attach the key to.
        key_type:  'sig', 'kem', or 'hybrid_kem'.
        purpose:   Usage label (mfa, session, storage, signing).
        algorithm: liboqs algorithm name. Defaults to user's effective PQC config.

    Returns:
        Persisted PQCKey instance.

    Raises:
        CryptoError: if key generation fails.
    """
    config = user.effective_pqc_config

    if algorithm is None:
        algorithm = config["sig"] if key_type == "sig" else config["kem"]

    if key_type == "hybrid_kem":
        from apps.crypto_bridge.hybrid_kem import hybrid_keygen

        kp = hybrid_keygen(config.get("hybrid_kem_context", "BlackPay-HybridKEM-v1"))
        pk_bytes = kp.public_key
        sk_bytes = kp.secret_key
    elif key_type == "sig":
        kp = sig_keygen(algorithm)
        pk_bytes = kp.public_key
        sk_bytes = kp.secret_key
    else:
        from apps.crypto_bridge.pqc import kem_keygen

        kp = kem_keygen(algorithm)
        pk_bytes = kp.public_key
        sk_bytes = kp.secret_key

    # Encrypt secret key
    fek = get_field_encryption_key()
    pk_hex = pk_bytes.hex()
    sk_hex = sk_bytes.hex()

    pqc_key = PQCKey(
        user=user,
        key_type=key_type,
        algorithm=algorithm,
        public_key_hex=pk_hex,
        purpose=purpose,
        is_active=True,
    )
    # ID must exist before encryption (AAD uses it)
    pqc_key.save()

    aad = str(pqc_key.id).encode()
    pqc_key.secret_key_encrypted = encrypt_field(sk_hex, fek, aad)
    pqc_key.save(update_fields=["secret_key_encrypted"])

    log.info(
        "PQC key generated",
        extra={"user_id": str(user.id), "algorithm": algorithm, "purpose": purpose},
    )
    return pqc_key


# ─── MFA session ─────────────────────────────────────────────────────────────


def create_mfa_session(user: User, method: str, request=None) -> MFASession:
    """
    Create a PQC or FIDO2 MFA session after successful password auth.

    Generates a cryptographically random 32-byte challenge and stores it.
    The challenge is sent to the client, which must sign it (PQC) or
    use it in an assertion (FIDO2).

    Args:
        user:    Authenticated user (password verified).
        method:  'pqc', 'fido2', or 'totp'.
        request: Django request (for IP/UA logging).

    Returns:
        MFASession instance.
    """
    challenge = secrets.token_bytes(32).hex()
    expires_at = timezone.now() + timedelta(seconds=MFA_SESSION_TTL_SECONDS)

    session = MFASession.objects.create(
        user=user,
        challenge=challenge,
        method=method,
        expires_at=expires_at,
        ip_address=_get_ip(request),
        user_agent=getattr(getattr(request, "META", {}), "get", lambda *a: "")(
            "HTTP_USER_AGENT", ""
        ),
    )
    log.debug(
        "MFA session created",
        extra={"user_id": str(user.id), "method": method, "session_id": str(session.id)},
    )
    return session


def verify_pqc_mfa(
    session: MFASession,
    signature_hex: str,
) -> bool:
    """
    Verify a PQC MFA response.

    The client must have signed the raw challenge bytes with their active
    ML-DSA secret key.  Verification uses the stored ML-DSA public key.

    Args:
        session:       MFASession with challenge bytes.
        signature_hex: Hex-encoded signature from the client.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        CryptoError: if the user has no active PQC signing key.
    """
    if session.is_expired:
        log.warning("PQC MFA: session expired", extra={"session_id": str(session.id)})
        return False

    if session.is_complete:
        log.warning("PQC MFA: session already used", extra={"session_id": str(session.id)})
        return False

    # Fetch the user's active MFA signing key
    try:
        pqc_key = PQCKey.objects.get(
            user=session.user,
            key_type="sig",
            purpose="mfa",
            is_active=True,
        )
    except PQCKey.DoesNotExist:
        raise CryptoError("User has no active PQC signing key configured for MFA.")
    except PQCKey.MultipleObjectsReturned:
        pqc_key = PQCKey.objects.filter(
            user=session.user, key_type="sig", purpose="mfa", is_active=True
        ).order_by("-created_at").first()

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False

    challenge_bytes = bytes.fromhex(session.challenge)
    pk_bytes = pqc_key.get_public_key_bytes()
    algorithm = pqc_key.algorithm

    valid = sig_verify(challenge_bytes, signature, pk_bytes, algorithm)
    if valid:
        session.is_complete = True
        session.save(update_fields=["is_complete"])
        log.info("PQC MFA verified", extra={"user_id": str(session.user_id)})
    else:
        log.warning("PQC MFA: invalid signature", extra={"user_id": str(session.user_id)})

    return valid


# ─── Platform signing key ─────────────────────────────────────────────────────


def sign_audit_entry(event_type: str, details: dict, timestamp: str) -> str:
    """
    Sign an audit log entry with the platform ML-DSA-65 signing key.

    The signed payload is: SHA-256(event_type || details_json || timestamp).

    Args:
        event_type: AuditLog.EventType value.
        details:    JSON-serialisable event details dict.
        timestamp:  ISO-8601 timestamp string.

    Returns:
        Hex-encoded signature string, or empty string if the platform key
        is not configured (logged as a warning).
    """
    import json

    platform_sk_hex = getattr(settings, "PLATFORM_SIGNING_SK_HEX", "")
    platform_pk_hex = getattr(settings, "PLATFORM_SIGNING_PK_HEX", "")
    platform_alg = getattr(settings, "PLATFORM_SIGNING_ALGORITHM", "ML-DSA-65")

    if not platform_sk_hex:
        log.warning("PLATFORM_SIGNING_SK_HEX not configured — audit entries unsigned")
        return ""

    payload = (
        event_type
        + "|"
        + json.dumps(details, sort_keys=True)
        + "|"
        + timestamp
    ).encode("utf-8")

    digest = hashlib.sha256(payload).digest()

    try:
        sk = bytes.fromhex(platform_sk_hex)
        sig = sig_sign(digest, sk, platform_alg)
        return sig.hex()
    except Exception as exc:
        log.error("Audit signing failed", exc_info=exc)
        return ""


def create_audit_log(
    event_type: str,
    user: Optional[User],
    details: dict,
    request=None,
) -> AuditLog:
    """
    Create a signed, immutable audit log entry.

    Args:
        event_type: AuditLog.EventType value.
        user:       Acting user (may be None for system events).
        details:    Event details dict (no secrets).
        request:    Django request for IP/UA capture.

    Returns:
        Persisted AuditLog instance.
    """
    now = timezone.now()
    sig = sign_audit_entry(event_type, details, now.isoformat())

    entry = AuditLog.objects.create(
        user=user,
        event_type=event_type,
        details=details,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
        signature_hex=sig,
    )
    return entry


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _get_ip(request) -> Optional[str]:
    """Extract client IP from request (handles X-Forwarded-For)."""
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _get_ua(request) -> str:
    """Extract User-Agent from request."""
    if request is None:
        return ""
    return request.META.get("HTTP_USER_AGENT", "")
