"""
apps/users/views.py
User registration, login, PQC-MFA, FIDO2, and profile management API views.

All endpoints that modify state require JWT authentication except:
  - POST /register
  - POST /login (first factor)
  - POST /mfa/pqc/challenge (uses mfa_session_id, not JWT)
  - POST /mfa/pqc/verify   (ditto)
  - POST /mfa/fido2/begin
  - POST /mfa/fido2/complete

Django Axes brute-force protection is active on all login/MFA endpoints.
"""

from __future__ import annotations

import logging
from typing import Any

from axes.decorators import axes_dispatch
from django.contrib.auth import login as django_login
from django.utils import timezone
from django.utils.decorators import method_decorator
from rest_framework import generics, permissions, status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.fido2_auth import (
    begin_authentication,
    begin_registration,
    complete_authentication,
    complete_registration,
)
from apps.users.models import FIDO2Credential, MFASession, PQCKey, User
from apps.users.pqc_auth import (
    create_audit_log,
    create_mfa_session,
    generate_user_pqc_keypair,
    verify_pqc_mfa,
)
from apps.users.serializers import (
    FIDO2AssertionSerializer,
    FIDO2CredentialSerializer,
    FIDO2RegisterCompleteSerializer,
    LoginSerializer,
    PQCKeyGenerateSerializer,
    PQCKeySerializer,
    PQCMFAChallengeSerializer,
    PQCMFAVerifySerializer,
    PasswordChangeSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
    UserUpdateSerializer,
)

log = logging.getLogger("blackpay.users.views")


def _issue_tokens(user: User) -> dict:
    """Issue JWT access + refresh token pair for the given user."""
    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }


# ─── Registration ─────────────────────────────────────────────────────────────


class RegisterView(APIView):
    """
    POST /api/v1/auth/register/
    Create a new BlackPay user account.

    Automatically generates a PQC signing key pair (ML-DSA-65) for MFA use.
    No authentication required.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Register a new user and generate their initial PQC key pair."""
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate default PQC signing key for MFA
        try:
            pqc_key = generate_user_pqc_keypair(user, key_type="sig", purpose="mfa")
        except Exception as exc:
            log.error("PQC keygen failed during registration", exc_info=exc)
            user.delete()
            return Response(
                {"detail": "Account creation failed during key generation."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        create_audit_log(
            event_type="login_success",
            user=user,
            details={"event": "registration", "pqc_key_id": str(pqc_key.id)},
            request=request,
        )

        return Response(
            {
                "user_id": str(user.id),
                "email": user.email,
                "pqc_public_key_hex": pqc_key.public_key_hex,
                "pqc_algorithm": pqc_key.algorithm,
                "message": "Account created. Store your PQC public key for MFA verification.",
            },
            status=status.HTTP_201_CREATED,
        )


# ─── Login (first factor) ─────────────────────────────────────────────────────


class LoginView(APIView):
    """
    POST /api/v1/auth/login/
    First-factor authentication: email + password.

    On success, returns a mfa_session_id.  The client must complete MFA
    before a JWT token is issued.

    Django Axes limits repeated failures per IP + username.
    """

    permission_classes = [permissions.AllowAny]

    @method_decorator(axes_dispatch)
    def dispatch(self, *args: Any, **kwargs: Any):
        return super().dispatch(*args, **kwargs)

    def post(self, request: Request) -> Response:
        """Authenticate credentials and create an MFA session."""
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user: User = serializer.validated_data["user"]

        method = user.mfa_method if user.mfa_enabled else "none"

        if method == "none":
            # MFA not configured — issue tokens directly (dev mode only)
            tokens = _issue_tokens(user)
            user.last_login_at = timezone.now()
            user.last_login_ip = request.META.get("REMOTE_ADDR")
            user.save(update_fields=["last_login_at", "last_login_ip"])
            create_audit_log("login_success", user, {"method": "password_only"}, request)
            return Response(tokens)

        session = create_mfa_session(user, method, request)
        return Response(
            {
                "mfa_required": True,
                "mfa_method": method,
                "mfa_session_id": str(session.id),
                "challenge": session.challenge,
            }
        )


# ─── PQC MFA ──────────────────────────────────────────────────────────────────


class PQCMFAChallengeView(APIView):
    """
    GET /api/v1/auth/mfa/pqc/challenge/?mfa_session_id=<uuid>
    Retrieve the raw challenge bytes for an MFA session.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request: Request) -> Response:
        """Return the challenge for the given MFA session."""
        session_id = request.query_params.get("mfa_session_id")
        if not session_id:
            raise ValidationError({"mfa_session_id": "Required."})

        try:
            session = MFASession.objects.get(id=session_id, method="pqc")
        except MFASession.DoesNotExist:
            raise NotFound("MFA session not found.")

        if session.is_expired:
            return Response(
                {"detail": "MFA session expired."},
                status=status.HTTP_410_GONE,
            )

        return Response({"challenge": session.challenge})


class PQCMFAVerifyView(APIView):
    """
    POST /api/v1/auth/mfa/pqc/verify/
    Verify ML-DSA signature and issue JWT tokens.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Verify PQC signature and issue tokens on success."""
        serializer = PQCMFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            session = MFASession.objects.select_related("user").get(
                id=serializer.validated_data["mfa_session_id"],
                method="pqc",
            )
        except MFASession.DoesNotExist:
            raise NotFound("MFA session not found.")

        valid = verify_pqc_mfa(session, serializer.validated_data["signature_hex"])
        if not valid:
            create_audit_log("mfa_failed", session.user, {"method": "pqc"}, request)
            return Response(
                {"detail": "Invalid signature."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user = session.user
        user.last_login_at = timezone.now()
        user.last_login_ip = request.META.get("REMOTE_ADDR")
        user.save(update_fields=["last_login_at", "last_login_ip"])

        tokens = _issue_tokens(user)
        create_audit_log("mfa_success", user, {"method": "pqc"}, request)
        return Response(tokens)


# ─── FIDO2 MFA ────────────────────────────────────────────────────────────────


class FIDO2RegisterBeginView(APIView):
    """POST /api/v1/auth/fido2/register/begin/ — Begin FIDO2 credential registration."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Return FIDO2 creation options for the client."""
        try:
            result = begin_registration(request.user)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result)


class FIDO2RegisterCompleteView(APIView):
    """POST /api/v1/auth/fido2/register/complete/ — Complete FIDO2 credential registration."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Verify attestation response and persist credential."""
        serializer = FIDO2RegisterCompleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        try:
            cred = complete_registration(
                user=request.user,
                session_key=d.get("session_key", f"fido2_reg_{request.user.id}"),
                response={"id": d["id"], "rawId": d["raw_id"], "response": d["response"]},
                device_name=d.get("device_name", "Security Key"),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        create_audit_log(
            "fido2_registered", request.user,
            {"credential_id": cred.credential_id, "device_name": cred.device_name},
            request,
        )
        return Response(FIDO2CredentialSerializer(cred).data, status=status.HTTP_201_CREATED)


class FIDO2AuthBeginView(APIView):
    """POST /api/v1/auth/fido2/auth/begin/ — Begin FIDO2 assertion for MFA session."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Return FIDO2 request options for the given MFA session."""
        session_id = request.data.get("mfa_session_id")
        if not session_id:
            raise ValidationError({"mfa_session_id": "Required."})

        try:
            session = MFASession.objects.select_related("user").get(
                id=session_id, method="fido2"
            )
        except MFASession.DoesNotExist:
            raise NotFound("MFA session not found.")

        if session.is_expired:
            return Response({"detail": "Session expired."}, status=status.HTTP_410_GONE)

        try:
            result = begin_authentication(session.user)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(result)


class FIDO2AuthCompleteView(APIView):
    """POST /api/v1/auth/fido2/auth/complete/ — Complete FIDO2 assertion and issue JWT."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Verify FIDO2 assertion and issue tokens on success."""
        serializer = FIDO2AssertionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        try:
            session = MFASession.objects.select_related("user").get(
                id=d["mfa_session_id"], method="fido2"
            )
        except MFASession.DoesNotExist:
            raise NotFound("MFA session not found.")

        if session.is_expired:
            return Response({"detail": "Session expired."}, status=status.HTTP_410_GONE)

        try:
            cred = complete_authentication(
                user=session.user,
                session_key=f"fido2_auth_{session.user_id}",
                response=request.data,
            )
        except ValueError as exc:
            create_audit_log("mfa_failed", session.user, {"method": "fido2"}, request)
            return Response({"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED)

        session.is_complete = True
        session.save(update_fields=["is_complete"])

        user = session.user
        user.last_login_at = timezone.now()
        user.last_login_ip = request.META.get("REMOTE_ADDR")
        user.save(update_fields=["last_login_at", "last_login_ip"])

        tokens = _issue_tokens(user)
        create_audit_log("mfa_success", user, {"method": "fido2"}, request)
        return Response(tokens)


# ─── Profile ──────────────────────────────────────────────────────────────────


class ProfileView(generics.RetrieveUpdateAPIView):
    """GET/PATCH /api/v1/auth/profile/ — Retrieve or update user profile."""

    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method in ("PUT", "PATCH"):
            return UserUpdateSerializer
        return UserProfileSerializer

    def get_object(self) -> User:
        return self.request.user


class PasswordChangeView(APIView):
    """POST /api/v1/auth/password/change/ — Change user password."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Verify current password and set new password."""
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        if not request.user.check_password(d["current_password"]):
            return Response(
                {"current_password": "Incorrect password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.user.set_password(d["new_password"])
        request.user.save(update_fields=["password"])
        create_audit_log("password_change", request.user, {}, request)
        return Response({"detail": "Password changed successfully."})


# ─── PQC Keys ─────────────────────────────────────────────────────────────────


class PQCKeyListView(generics.ListAPIView):
    """GET /api/v1/auth/keys/ — List the current user's PQC key pairs."""

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PQCKeySerializer

    def get_queryset(self):
        return PQCKey.objects.filter(user=self.request.user, is_active=True)


class PQCKeyGenerateView(APIView):
    """POST /api/v1/auth/keys/generate/ — Generate a new PQC key pair."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Generate and persist a new PQC key pair for the authenticated user."""
        serializer = PQCKeyGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        try:
            pqc_key = generate_user_pqc_keypair(
                user=request.user,
                key_type=d["key_type"],
                purpose=d["purpose"],
                algorithm=d["algorithm"],
            )
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        create_audit_log(
            "key_generated", request.user,
            {"key_id": str(pqc_key.id), "algorithm": pqc_key.algorithm},
            request,
        )
        return Response(PQCKeySerializer(pqc_key).data, status=status.HTTP_201_CREATED)


# ─── FIDO2 Credential management ──────────────────────────────────────────────


class FIDO2CredentialListView(generics.ListAPIView):
    """GET /api/v1/auth/fido2/credentials/ — List registered FIDO2 credentials."""

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FIDO2CredentialSerializer

    def get_queryset(self):
        return FIDO2Credential.objects.filter(user=self.request.user, is_active=True)


class FIDO2CredentialDeleteView(generics.DestroyAPIView):
    """DELETE /api/v1/auth/fido2/credentials/<pk>/ — Deactivate a FIDO2 credential."""

    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return FIDO2Credential.objects.filter(user=self.request.user, is_active=True)

    def perform_destroy(self, instance: FIDO2Credential) -> None:
        instance.is_active = False
        instance.save(update_fields=["is_active"])
        create_audit_log(
            "fido2_registered", self.request.user,
            {"action": "deactivated", "credential_id": instance.credential_id},
            self.request,
        )
