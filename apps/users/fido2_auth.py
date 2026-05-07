"""
apps/users/fido2_auth.py
FIDO2/WebAuthn registration and authentication helpers.

Uses the `fido2` library (Yubico).  All credential data is persisted
to FIDO2Credential model instances.

Registration flow:
  1. Server calls begin_registration() → returns PublicKeyCredentialCreationOptions
  2. Client performs authenticator gesture, returns attestation response
  3. Server calls complete_registration(response) → persists FIDO2Credential

Authentication flow:
  1. Server calls begin_authentication() → returns PublicKeyCredentialRequestOptions
  2. Client performs authenticator gesture, returns assertion response
  3. Server calls complete_authentication(response) → verifies and updates sign_count
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Optional

from django.conf import settings
from django.utils import timezone
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from apps.users.models import FIDO2Credential, User

log = logging.getLogger("blackpay.users.fido2")


def _get_server() -> Fido2Server:
    """
    Build and return a configured Fido2Server instance.

    Uses FIDO2_RP_ID and FIDO2_ORIGIN from Django settings.
    """
    rp = PublicKeyCredentialRpEntity(
        id=settings.FIDO2_RP_ID,
        name=settings.FIDO2_RP_NAME,
    )
    return Fido2Server(rp, verify_origin=lambda origin: origin == settings.FIDO2_ORIGIN)


def _b64url_decode(value: str) -> bytes:
    """Decode a base64url string (with or without padding)."""
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return base64.urlsafe_b64decode(value)


# ─── Registration ─────────────────────────────────────────────────────────────


def begin_registration(user: User) -> dict:
    """
    Begin FIDO2 credential registration for a user.

    Generates a PublicKeyCredentialCreationOptions challenge and stores
    the state in the user's session (via Django cache).

    Args:
        user: User who is registering a new authenticator.

    Returns:
        Dict with 'options' (JSON-serialisable creation options) and 'session_key'
        (cache key where server state is stored — must be provided at completion).
    """
    from django.core.cache import cache

    server = _get_server()

    # Collect already-registered credential IDs to exclude from re-registration
    existing_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=_b64url_decode(cred.credential_id),
        )
        for cred in FIDO2Credential.objects.filter(user=user, is_active=True)
    ]

    user_entity = PublicKeyCredentialUserEntity(
        id=str(user.id).encode("utf-8"),
        name=user.email,
        display_name=user.email,
    )

    options, state = server.register_begin(
        user=user_entity,
        credentials=existing_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    session_key = f"fido2_reg_{user.id}"
    cache.set(session_key, state, timeout=300)  # 5 min

    log.debug("FIDO2 registration begun", extra={"user_id": str(user.id)})

    # fido2 library returns cbor-encoded objects; convert to JSON-safe dict
    return {
        "session_key": session_key,
        "options": options,
    }


def complete_registration(
    user: User,
    session_key: str,
    response: dict,
    device_name: str = "Security Key",
) -> FIDO2Credential:
    """
    Complete FIDO2 credential registration.

    Verifies the attestation response and persists the credential.

    Args:
        user:        User registering the credential.
        session_key: Cache key from begin_registration().
        response:    Attestation response dict from the client.
        device_name: Human-readable label for this authenticator.

    Returns:
        Persisted FIDO2Credential instance.

    Raises:
        ValueError: if the session is expired or the attestation is invalid.
    """
    from django.core.cache import cache

    state = cache.get(session_key)
    if not state:
        raise ValueError("FIDO2 registration session expired or not found.")

    server = _get_server()

    # Reconstruct the AuthenticatorAttestationResponse from the client dict
    try:
        credential = _parse_attestation_response(response)
        auth_data = server.register_complete(state, credential)
    except Exception as exc:
        log.warning("FIDO2 registration failed", exc_info=exc, extra={"user_id": str(user.id)})
        raise ValueError(f"FIDO2 registration failed: {exc}") from exc

    cache.delete(session_key)

    # Encode credential ID as base64url for storage
    credential_id_b64 = base64.urlsafe_b64encode(
        auth_data.credential_data.credential_id
    ).rstrip(b"=").decode()

    public_key_cbor = base64.b64encode(
        bytes(auth_data.credential_data.public_key)
    ).decode()

    cred = FIDO2Credential.objects.create(
        user=user,
        credential_id=credential_id_b64,
        public_key_cbor=public_key_cbor,
        sign_count=auth_data.counter,
        device_name=device_name,
        aaguid=str(auth_data.credential_data.aaguid) if auth_data.credential_data.aaguid else "",
        transports=list(getattr(auth_data, "transports", []) or []),
    )

    log.info(
        "FIDO2 credential registered",
        extra={"user_id": str(user.id), "credential_id": credential_id_b64},
    )
    return cred


# ─── Authentication ───────────────────────────────────────────────────────────


def begin_authentication(user: User) -> dict:
    """
    Begin FIDO2 authentication for a user.

    Generates an assertion challenge for the user's registered credentials.

    Args:
        user: User who is authenticating.

    Returns:
        Dict with 'session_key' and 'options' (JSON-serialisable request options).

    Raises:
        ValueError: if the user has no registered FIDO2 credentials.
    """
    from django.core.cache import cache

    credentials_qs = FIDO2Credential.objects.filter(user=user, is_active=True)
    if not credentials_qs.exists():
        raise ValueError("No FIDO2 credentials registered for this user.")

    server = _get_server()

    allowed_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=_b64url_decode(cred.credential_id),
        )
        for cred in credentials_qs
    ]

    options, state = server.authenticate_begin(
        credentials=allowed_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    session_key = f"fido2_auth_{user.id}"
    cache.set(session_key, state, timeout=300)

    log.debug("FIDO2 authentication begun", extra={"user_id": str(user.id)})
    return {"session_key": session_key, "options": options}


def complete_authentication(
    user: User,
    session_key: str,
    response: dict,
) -> FIDO2Credential:
    """
    Complete FIDO2 authentication.

    Verifies the assertion response against the user's registered credentials.
    Updates the sign counter to detect cloned authenticators.

    Args:
        user:        User authenticating.
        session_key: Cache key from begin_authentication().
        response:    Assertion response dict from the client.

    Returns:
        The matching FIDO2Credential that was used.

    Raises:
        ValueError: on invalid assertion or cloned authenticator detected.
    """
    from django.core.cache import cache

    state = cache.get(session_key)
    if not state:
        raise ValueError("FIDO2 authentication session expired or not found.")

    server = _get_server()

    # Load all active credentials for verification
    credentials_qs = FIDO2Credential.objects.filter(user=user, is_active=True)
    credentials_map = {
        _b64url_decode(c.credential_id): c for c in credentials_qs
    }

    # Build server credential objects with stored public keys and sign counts
    server_credentials = []
    for cred_id_bytes, cred in credentials_map.items():
        from fido2.webauthn import AttestedCredentialData

        pk_cbor = base64.b64decode(cred.public_key_cbor)
        acd = AttestedCredentialData.create(
            aaguid=b"\x00" * 16,
            credential_id=cred_id_bytes,
            public_key=pk_cbor,
        )
        server_credentials.append(acd)

    try:
        auth_data, credential_id, new_sign_count = server.authenticate_complete(
            state=state,
            credentials=server_credentials,
            credential_id=_b64url_decode(response.get("id", "")),
            client_data=_b64url_decode(response.get("response", {}).get("clientDataJSON", "")),
            auth_data=_b64url_decode(response.get("response", {}).get("authenticatorData", "")),
            signature=_b64url_decode(response.get("response", {}).get("signature", "")),
        )
    except Exception as exc:
        log.warning("FIDO2 authentication failed", exc_info=exc)
        raise ValueError(f"FIDO2 authentication failed: {exc}") from exc

    cache.delete(session_key)

    # Find and update the matching credential
    cred_id_b64 = base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode()
    matched_cred = FIDO2Credential.objects.get(credential_id=cred_id_b64, user=user)

    # Clone detection: new sign count must exceed stored count
    if new_sign_count > 0 and new_sign_count <= matched_cred.sign_count:
        log.error(
            "FIDO2 cloned authenticator detected",
            extra={
                "user_id": str(user.id),
                "stored_count": matched_cred.sign_count,
                "received_count": new_sign_count,
            },
        )
        raise ValueError("Cloned authenticator detected. Credential has been deactivated.")

    matched_cred.sign_count = new_sign_count
    matched_cred.last_used_at = timezone.now()
    matched_cred.save(update_fields=["sign_count", "last_used_at"])

    log.info("FIDO2 authentication ok", extra={"user_id": str(user.id)})
    return matched_cred


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _parse_attestation_response(response: dict) -> Any:
    """
    Parse a JSON attestation response dict into the fido2 library object.

    The client sends base64url-encoded fields; this helper decodes them.
    """
    from fido2.client import ClientData

    raw_id = _b64url_decode(response.get("rawId", response.get("id", "")))
    client_data_json = _b64url_decode(
        response.get("response", {}).get("clientDataJSON", "")
    )
    attestation_object = _b64url_decode(
        response.get("response", {}).get("attestationObject", "")
    )

    # fido2 >=1.0 API
    from fido2.cbor import decode as cbor_decode
    from fido2.webauthn import AuthenticatorAttestationResponse

    return AuthenticatorAttestationResponse(
        client_data=ClientData(client_data_json),
        attestation_object=cbor_decode(attestation_object),
    )
