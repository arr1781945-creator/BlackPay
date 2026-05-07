"""
apps/users/models.py
User, PQCKey, FIDO2Credential, MFASession, and AuditLog models.

All PKs are UUIDs.  Sensitive fields (email, phone) are encrypted at rest
using AES-256-GCM via the crypto_bridge field helpers.
"""

from __future__ import annotations

import uuid
from typing import Any

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


# ─── Manager ─────────────────────────────────────────────────────────────────


class UserManager(BaseUserManager):
    """Custom manager for the BlackPay User model."""

    def create_user(
        self,
        email: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> "User":
        """Create and persist a regular user."""
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str, **extra_fields: Any) -> "User":
        """Create a Django superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        return self.create_user(email, password, **extra_fields)


# ─── User ─────────────────────────────────────────────────────────────────────


class User(AbstractBaseUser, PermissionsMixin):
    """
    BlackPay user account.

    Authentication is email + password (bcrypt via Django), followed by
    PQC-MFA (ML-DSA signature challenge) or FIDO2/WebAuthn.
    Sensitive PII fields are AES-256-GCM encrypted at the application layer.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # ── Identity ──────────────────────────────────────────────────────────────
    email = models.EmailField(unique=True, db_index=True)
    email_verified = models.BooleanField(default=False)

    # Encrypted PII fields (stored as base64 blobs)
    phone_encrypted = models.TextField(blank=True, default="")
    full_name_encrypted = models.TextField(blank=True, default="")

    # ── Status ────────────────────────────────────────────────────────────────
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False, help_text="KYC verified")

    # ── MFA ───────────────────────────────────────────────────────────────────
    mfa_enabled = models.BooleanField(default=False)
    mfa_method = models.CharField(
        max_length=20,
        choices=[("pqc", "PQC-MFA"), ("fido2", "FIDO2/WebAuthn"), ("totp", "TOTP")],
        default="pqc",
    )

    # ── Tenant / organisation ─────────────────────────────────────────────────
    tenant_id = models.UUIDField(null=True, blank=True, db_index=True)
    pqc_config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Per-user PQC algorithm overrides (falls back to tenant config)",
    )

    # ── Compliance ────────────────────────────────────────────────────────────
    gdpr_consent_at = models.DateTimeField(null=True, blank=True)
    data_retention_until = models.DateTimeField(null=True, blank=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        db_table = "bp_users"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"<User {self.email}>"

    @property
    def effective_pqc_config(self) -> dict:
        """
        Merge user-level PQC config over tenant defaults.
        Returns a complete config dict.
        """
        from blackpay.pqc_config import DEFAULT_TENANT_PQC_CONFIG

        base = dict(DEFAULT_TENANT_PQC_CONFIG)
        base.update(self.pqc_config or {})
        return base


# ─── PQC Key ─────────────────────────────────────────────────────────────────


class PQCKey(models.Model):
    """
    A Post-Quantum Cryptography key pair belonging to a user.

    Secret keys are stored encrypted with the platform FIELD_ENCRYPTION_KEY.
    Public keys are stored in plain — they are public by nature.
    One user may have multiple keys (e.g. KEM key + SIG key, per algorithm).
    """

    class KeyType(models.TextChoices):
        KEM = "kem", "Key Encapsulation"
        SIG = "sig", "Digital Signature"
        HYBRID_KEM = "hybrid_kem", "Hybrid KEM (X25519 + ML-KEM)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="pqc_keys")

    key_type = models.CharField(max_length=20, choices=KeyType.choices)
    algorithm = models.CharField(max_length=80, help_text="liboqs algorithm identifier")

    # Public key stored as hex (safe to read without decryption)
    public_key_hex = models.TextField()

    # Secret key stored as AES-256-GCM encrypted base64 blob
    secret_key_encrypted = models.TextField()

    is_active = models.BooleanField(default=True)
    purpose = models.CharField(
        max_length=40,
        choices=[
            ("mfa", "MFA Authentication"),
            ("session", "Session Key Exchange"),
            ("storage", "Storage Encryption"),
            ("signing", "Transaction Signing"),
        ],
        default="mfa",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "bp_pqc_keys"
        indexes = [
            models.Index(fields=["user", "key_type", "is_active"]),
            models.Index(fields=["algorithm"]),
        ]

    def __str__(self) -> str:
        return f"<PQCKey {self.key_type}/{self.algorithm} user={self.user_id}>"

    def get_public_key_bytes(self) -> bytes:
        """Return the public key as raw bytes."""
        return bytes.fromhex(self.public_key_hex)

    def get_secret_key_bytes(self) -> bytes:
        """
        Decrypt and return the secret key bytes.
        Requires FIELD_ENCRYPTION_KEY to be configured.
        """
        from apps.crypto_bridge.symmetric import (
            decrypt_field,
            get_field_encryption_key,
        )

        fek = get_field_encryption_key()
        aad = str(self.id).encode()
        return bytes.fromhex(decrypt_field(self.secret_key_encrypted, fek, aad))

    def set_secret_key_bytes(self, sk: bytes) -> None:
        """Encrypt and store the secret key bytes."""
        from apps.crypto_bridge.symmetric import encrypt_field, get_field_encryption_key

        fek = get_field_encryption_key()
        aad = str(self.id).encode()
        self.secret_key_encrypted = encrypt_field(sk.hex(), fek, aad)


# ─── FIDO2 Credential ─────────────────────────────────────────────────────────


class FIDO2Credential(models.Model):
    """
    A FIDO2/WebAuthn credential registered to a user.

    Credential IDs and public keys are stored as-is (not sensitive in isolation).
    The credential is bound to the relying party (RP) ID.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="fido2_credentials")

    # FIDO2 credential ID (base64url)
    credential_id = models.TextField(unique=True, db_index=True)

    # CBOR-encoded public key (base64)
    public_key_cbor = models.TextField()

    # Authenticator AAGUID (identifies authenticator make/model)
    aaguid = models.CharField(max_length=36, blank=True)

    # Signature counter — used for clone detection
    sign_count = models.PositiveBigIntegerField(default=0)

    # Human-readable name set by user
    device_name = models.CharField(max_length=100, default="Security Key")

    # Attestation type: none, indirect, direct, enterprise
    attestation_type = models.CharField(max_length=20, default="none")

    # Transport hints: usb, nfc, ble, internal, hybrid
    transports = models.JSONField(default=list)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "bp_fido2_credentials"
        indexes = [models.Index(fields=["user", "is_active"])]

    def __str__(self) -> str:
        return f"<FIDO2 {self.device_name} user={self.user_id}>"


# ─── MFA Session ─────────────────────────────────────────────────────────────


class MFASession(models.Model):
    """
    Short-lived session created after password auth, before MFA completion.

    The JWT access token is only issued after MFA succeeds and this record
    is marked complete.  Sessions expire after 5 minutes if unused.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="mfa_sessions")

    # Random challenge sent to the client for MFA
    challenge = models.TextField()

    # Which MFA method this session expects
    method = models.CharField(
        max_length=20,
        choices=[("pqc", "PQC"), ("fido2", "FIDO2"), ("totp", "TOTP")],
    )

    is_complete = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    # IP address of the session creator
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        db_table = "bp_mfa_sessions"
        indexes = [models.Index(fields=["user", "is_complete", "expires_at"])]

    @property
    def is_expired(self) -> bool:
        """Return True if the session has passed its expiry time."""
        return timezone.now() > self.expires_at


# ─── Audit Log ────────────────────────────────────────────────────────────────


class AuditLog(models.Model):
    """
    Immutable audit trail for all security-relevant events.

    Once created, records are never updated.  Deletion is only permitted
    via the GDPR erasure flow (which replaces PII with REDACTED tokens).
    Each record is signed with the platform's ML-DSA-65 signing key.
    """

    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Login Success"
        LOGIN_FAILED = "login_failed", "Login Failed"
        MFA_SUCCESS = "mfa_success", "MFA Success"
        MFA_FAILED = "mfa_failed", "MFA Failed"
        LOGOUT = "logout", "Logout"
        PASSWORD_CHANGE = "password_change", "Password Change"
        KEY_GENERATED = "key_generated", "PQC Key Generated"
        KEY_ROTATED = "key_rotated", "PQC Key Rotated"
        FIDO2_REGISTERED = "fido2_registered", "FIDO2 Credential Registered"
        TRANSACTION_CREATED = "transaction_created", "Transaction Created"
        TRANSACTION_COMPLETED = "transaction_completed", "Transaction Completed"
        TRANSACTION_FAILED = "transaction_failed", "Transaction Failed"
        GDPR_EXPORT = "gdpr_export", "GDPR Data Export"
        GDPR_ERASURE = "gdpr_erasure", "GDPR Erasure Request"
        ADMIN_ACTION = "admin_action", "Admin Action"
        SUSPICIOUS_ACTIVITY = "suspicious_activity", "Suspicious Activity"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Actor — may be null for system events
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    event_type = models.CharField(max_length=40, choices=EventType.choices, db_index=True)

    # Structured event payload (no secrets)
    details = models.JSONField(default=dict)

    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_id = models.UUIDField(null=True, blank=True)

    # Integrity signature (ML-DSA-65 over event_type + details + timestamp)
    signature_hex = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "bp_audit_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "event_type"]),
            models.Index(fields=["event_type", "created_at"]),
            models.Index(fields=["ip_address", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"<AuditLog {self.event_type} at {self.created_at}>"
