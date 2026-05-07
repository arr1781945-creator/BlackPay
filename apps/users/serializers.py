"""
apps/users/serializers.py
DRF serializers for user registration, login, MFA, and profile management.
"""

from __future__ import annotations

import re
from typing import Any

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from apps.users.models import FIDO2Credential, MFASession, PQCKey, User


# ─── Registration ─────────────────────────────────────────────────────────────


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Validate and create a new BlackPay user.

    Password is validated against Django's AUTH_PASSWORD_VALIDATORS.
    GDPR consent is required.
    """

    password = serializers.CharField(
        write_only=True,
        min_length=12,
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )
    gdpr_consent = serializers.BooleanField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "password_confirm", "gdpr_consent"]

    def validate_email(self, value: str) -> str:
        """Normalise and ensure the email is not already registered."""
        value = value.lower().strip()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already registered.")
        return value

    def validate_password(self, value: str) -> str:
        """Run Django's built-in password validators."""
        validate_password(value)
        return value

    def validate_gdpr_consent(self, value: bool) -> bool:
        """GDPR consent is mandatory for all users."""
        if not value:
            raise serializers.ValidationError(
                "You must accept the privacy policy to create an account."
            )
        return value

    def validate(self, attrs: dict) -> dict:
        if attrs["password"] != attrs.pop("password_confirm"):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return attrs

    def create(self, validated_data: dict) -> User:
        validated_data.pop("gdpr_consent")
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            gdpr_consent_at=timezone.now(),
        )
        return user


# ─── Login ────────────────────────────────────────────────────────────────────


class LoginSerializer(serializers.Serializer):
    """
    First-factor authentication: email + password.
    Returns a short-lived MFA session token on success.
    """

    email = serializers.EmailField()
    password = serializers.CharField(style={"input_type": "password"})

    def validate(self, attrs: dict) -> dict:
        """Authenticate credentials and return the user if valid."""
        user = authenticate(
            request=self.context.get("request"),
            username=attrs["email"].lower().strip(),
            password=attrs["password"],
        )
        if not user:
            raise AuthenticationFailed("Invalid email or password.")
        if not user.is_active:
            raise AuthenticationFailed("This account has been deactivated.")
        attrs["user"] = user
        return attrs


# ─── MFA ──────────────────────────────────────────────────────────────────────


class PQCMFAChallengeSerializer(serializers.Serializer):
    """
    Request a PQC MFA challenge.
    Client sends the MFA session token; server responds with a challenge.
    """

    mfa_session_id = serializers.UUIDField()


class PQCMFAVerifySerializer(serializers.Serializer):
    """
    Verify a PQC MFA challenge response.

    The client signs the challenge bytes with their ML-DSA secret key
    and sends the signature back.
    """

    mfa_session_id = serializers.UUIDField()
    signature_hex = serializers.CharField(
        min_length=64,
        help_text="Hex-encoded ML-DSA signature over the challenge bytes",
    )

    def validate_signature_hex(self, value: str) -> str:
        """Ensure the signature is valid hex."""
        try:
            bytes.fromhex(value)
        except ValueError:
            raise serializers.ValidationError("signature_hex must be a valid hex string.")
        return value


class FIDO2AssertionSerializer(serializers.Serializer):
    """FIDO2/WebAuthn assertion response from the authenticator."""

    mfa_session_id = serializers.UUIDField()
    credential_id = serializers.CharField()
    authenticator_data = serializers.CharField(help_text="Base64url-encoded authenticatorData")
    client_data_json = serializers.CharField(help_text="Base64url-encoded clientDataJSON")
    signature = serializers.CharField(help_text="Base64url-encoded signature")
    user_handle = serializers.CharField(required=False, allow_blank=True)


# ─── Profile ──────────────────────────────────────────────────────────────────


class UserProfileSerializer(serializers.ModelSerializer):
    """Read-only public user profile (no PII)."""

    class Meta:
        model = User
        fields = [
            "id", "email", "is_verified", "mfa_enabled", "mfa_method",
            "created_at", "last_login_at",
        ]
        read_only_fields = fields


class UserUpdateSerializer(serializers.ModelSerializer):
    """Allow users to update their MFA method and PQC config."""

    class Meta:
        model = User
        fields = ["mfa_method", "pqc_config"]

    def validate_pqc_config(self, value: dict) -> dict:
        """Validate the requested PQC algorithm config."""
        from blackpay.pqc_config import validate_tenant_config

        is_valid, errors = validate_tenant_config(value)
        if not is_valid:
            raise serializers.ValidationError(errors)
        return value


class PasswordChangeSerializer(serializers.Serializer):
    """Change password — requires current password confirmation."""

    current_password = serializers.CharField(style={"input_type": "password"})
    new_password = serializers.CharField(
        min_length=12,
        style={"input_type": "password"},
    )
    new_password_confirm = serializers.CharField(style={"input_type": "password"})

    def validate_new_password(self, value: str) -> str:
        validate_password(value)
        return value

    def validate(self, attrs: dict) -> dict:
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "New passwords do not match."}
            )
        return attrs


# ─── PQC Keys ─────────────────────────────────────────────────────────────────


class PQCKeySerializer(serializers.ModelSerializer):
    """Public representation of a PQC key (never exposes secret key)."""

    class Meta:
        model = PQCKey
        fields = [
            "id", "key_type", "algorithm", "public_key_hex",
            "is_active", "purpose", "created_at", "expires_at",
        ]
        read_only_fields = fields


class PQCKeyGenerateSerializer(serializers.Serializer):
    """Request generation of a new PQC key pair."""

    key_type = serializers.ChoiceField(choices=PQCKey.KeyType.choices)
    algorithm = serializers.CharField(max_length=80)
    purpose = serializers.ChoiceField(
        choices=["mfa", "session", "storage", "signing"],
        default="mfa",
    )

    def validate_algorithm(self, value: str) -> str:
        """Ensure the requested algorithm is supported."""
        from apps.crypto_bridge.pqc import supported_kems, supported_sigs

        key_type = self.initial_data.get("key_type")
        supported = supported_kems() if key_type in ("kem", "hybrid_kem") else supported_sigs()
        if value not in supported:
            raise serializers.ValidationError(
                f"Algorithm '{value}' is not supported. Available: {supported}"
            )
        return value


# ─── FIDO2 Credentials ────────────────────────────────────────────────────────


class FIDO2CredentialSerializer(serializers.ModelSerializer):
    """Public representation of a registered FIDO2 credential."""

    class Meta:
        model = FIDO2Credential
        fields = [
            "id", "device_name", "aaguid", "sign_count",
            "attestation_type", "transports", "is_active",
            "created_at", "last_used_at",
        ]
        read_only_fields = fields


class FIDO2RegisterCompleteSerializer(serializers.Serializer):
    """Complete FIDO2 registration with attestation response."""

    device_name = serializers.CharField(max_length=100, default="Security Key")
    id = serializers.CharField(help_text="Base64url credential ID")
    raw_id = serializers.CharField(help_text="Base64url rawId")
    response = serializers.DictField(help_text="Attestation response dict")
    type = serializers.CharField(default="public-key")


# ─── Audit Log ────────────────────────────────────────────────────────────────


class AuditLogSerializer(serializers.Serializer):
    """Read-only audit log entry — returned by the compliance API."""

    id = serializers.UUIDField()
    event_type = serializers.CharField()
    details = serializers.DictField()
    ip_address = serializers.IPAddressField(allow_null=True)
    created_at = serializers.DateTimeField()
