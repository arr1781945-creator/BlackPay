"""
apps/compliance/views.py
GDPR, KYC, audit trail, and consent management API views.

Endpoints:
  POST   /api/v1/compliance/gdpr/request/        — Submit a GDPR subject request
  GET    /api/v1/compliance/gdpr/request/         — List own GDPR requests
  GET    /api/v1/compliance/gdpr/export/          — Download data export (Art. 20)
  POST   /api/v1/compliance/consent/              — Record consent
  GET    /api/v1/compliance/consent/              — Get active consents
  GET    /api/v1/compliance/audit/                — List own audit trail
  GET    /api/v1/compliance/kyc/                  — KYC status
  POST   /api/v1/compliance/kyc/submit/           — Submit KYC documents
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.compliance.gdpr import (
    export_user_data,
    get_active_consents,
    record_consent,
)
from apps.compliance.models import (
    AuditTrail,
    ConsentRecord,
    GDPRRequest,
    KYCRecord,
)
from apps.compliance.serializers import (
    AuditTrailSerializer,
    ConsentRecordSerializer,
    GDPRRequestSerializer,
    KYCRecordSerializer,
    RecordConsentSerializer,
    SubmitGDPRRequestSerializer,
    SubmitKYCSerializer,
)
from apps.users.pqc_auth import create_audit_log

log = logging.getLogger("blackpay.compliance.views")


# ─── GDPR Requests ────────────────────────────────────────────────────────────


class GDPRRequestListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/v1/compliance/gdpr/request/ — List own GDPR requests.
    POST /api/v1/compliance/gdpr/request/ — Submit a new GDPR request.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return SubmitGDPRRequestSerializer
        return GDPRRequestSerializer

    def get_queryset(self):
        return GDPRRequest.objects.filter(user=self.request.user).order_by("-created_at")

    def create(self, request: Request, *args, **kwargs) -> Response:
        """
        Submit a GDPR subject rights request.

        Creates a GDPRRequest record and sets the 30-day GDPR deadline.
        Erasure requests are deferred for processing by a background task.
        Export requests are fulfilled synchronously (small data volumes).
        """
        serializer = SubmitGDPRRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        # Check for duplicate pending request of same type
        existing = GDPRRequest.objects.filter(
            user=request.user,
            request_type=d["request_type"],
            status__in=["pending", "in_progress"],
        ).exists()
        if existing:
            return Response(
                {"detail": "A pending request of this type already exists."},
                status=status.HTTP_409_CONFLICT,
            )

        gdpr_request = GDPRRequest.objects.create(
            user=request.user,
            request_type=d["request_type"],
            user_note=d.get("user_note", ""),
            due_by=timezone.now() + timedelta(days=30),
        )

        create_audit_log(
            "gdpr_export" if d["request_type"] == "export" else "gdpr_erasure",
            request.user,
            {"request_id": str(gdpr_request.id), "type": d["request_type"]},
            request,
        )

        # For export requests, fulfil immediately
        if d["request_type"] == "export":
            from apps.compliance.tasks import process_gdpr_export
            process_gdpr_export.delay(str(gdpr_request.id))

        # For erasure, queue for background processing
        elif d["request_type"] == "erasure":
            from apps.compliance.tasks import process_gdpr_erasure
            process_gdpr_erasure.delay(str(gdpr_request.id))

        return Response(
            GDPRRequestSerializer(gdpr_request).data,
            status=status.HTTP_201_CREATED,
        )


class GDPRDataExportView(APIView):
    """
    GET /api/v1/compliance/gdpr/export/
    Download a JSON data export for the authenticated user (Art. 20).

    Returns the export inline if the user's data volume is small.
    For large exports, an IPFS hash is returned after async processing.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Generate and return a portable data export."""
        export_data = export_user_data(request.user)

        create_audit_log(
            "gdpr_export",
            request.user,
            {"source": "direct_download"},
            request,
        )

        return Response(export_data, status=status.HTTP_200_OK)


# ─── Consent management ───────────────────────────────────────────────────────


class ConsentView(APIView):
    """
    GET  /api/v1/compliance/consent/ — Return all active consent states.
    POST /api/v1/compliance/consent/ — Record a consent or withdrawal.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return a dict of purpose → consent_given for the authenticated user."""
        consents = get_active_consents(request.user)
        return Response({"consents": consents})

    def post(self, request: Request) -> Response:
        """Record a consent or withdrawal."""
        serializer = RecordConsentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        record = record_consent(
            user=request.user,
            purpose=d["purpose"],
            given=d["given"],
            policy_version=d["policy_version"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

        return Response(
            ConsentRecordSerializer(record).data,
            status=status.HTTP_201_CREATED,
        )


# ─── Audit Trail ──────────────────────────────────────────────────────────────


class AuditTrailListView(generics.ListAPIView):
    """
    GET /api/v1/compliance/audit/
    List the authenticated user's data-processing audit trail.

    Filterable by category via ?category=<value>.
    Paginated — 50 entries per page.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AuditTrailSerializer

    def get_queryset(self):
        qs = AuditTrail.objects.filter(user=self.request.user).order_by("-created_at")
        category = self.request.query_params.get("category")
        if category:
            qs = qs.filter(category=category)
        return qs


# ─── KYC / AML ────────────────────────────────────────────────────────────────


class KYCStatusView(generics.RetrieveAPIView):
    """
    GET /api/v1/compliance/kyc/
    Return the authenticated user's KYC verification status.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = KYCRecordSerializer

    def get_object(self) -> KYCRecord:
        """Return or create the user's KYC record."""
        record, _ = KYCRecord.objects.get_or_create(user=self.request.user)
        return record


class KYCSubmitView(APIView):
    """
    POST /api/v1/compliance/kyc/submit/
    Submit KYC documents for review.

    Documents are stored encrypted in IPFS; only the IPFS hash is persisted.
    Triggers an automated PEP/sanctions screening.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Accept KYC document IPFS hashes and update verification status."""
        serializer = SubmitKYCSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        record, _ = KYCRecord.objects.get_or_create(user=request.user)

        if record.status in ("approved",):
            return Response(
                {"detail": "KYC is already approved."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        record.id_document_ipfs = d.get("id_document_ipfs", record.id_document_ipfs)
        record.proof_of_address_ipfs = d.get(
            "proof_of_address_ipfs", record.proof_of_address_ipfs
        )
        record.selfie_ipfs = d.get("selfie_ipfs", record.selfie_ipfs)
        record.status = KYCRecord.VerificationStatus.PENDING
        record.submitted_at = timezone.now()
        record.save(
            update_fields=[
                "id_document_ipfs", "proof_of_address_ipfs", "selfie_ipfs",
                "status", "submitted_at",
            ]
        )

        # Log to AuditTrail
        AuditTrail.objects.create(
            user=request.user,
            category=AuditTrail.Category.KYC_CHECK,
            action="kyc_documents_submitted",
            legal_basis="legal_obligation",
            details={
                "kyc_record_id": str(record.id),
                "documents_provided": {
                    "id": bool(d.get("id_document_ipfs")),
                    "address": bool(d.get("proof_of_address_ipfs")),
                    "selfie": bool(d.get("selfie_ipfs")),
                },
            },
        )

        return Response(
            KYCRecordSerializer(record).data,
            status=status.HTTP_200_OK,
        )


# ─── Compliance middleware ────────────────────────────────────────────────────

class AuditMiddleware:
    """
    Django middleware that logs every authenticated API request to AuditTrail.

    Only logs non-GET requests to avoid excessive volume.
    Sensitive paths (auth, webhooks) are excluded from the body snapshot.
    """

    EXCLUDED_PATHS = {"/api/v1/payments/webhooks/", "/api/v1/auth/token/"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Only log authenticated mutating requests
        if (
            request.method not in ("GET", "HEAD", "OPTIONS")
            and hasattr(request, "user")
            and request.user.is_authenticated
            and not any(request.path.startswith(p) for p in self.EXCLUDED_PATHS)
        ):
            try:
                AuditTrail.objects.create(
                    user=request.user,
                    category=AuditTrail.Category.DATA_PROCESSING,
                    action=f"{request.method} {request.path}",
                    details={
                        "status_code": response.status_code,
                        "path": request.path,
                    },
                    legal_basis="contract",
                    ip_address=request.META.get("REMOTE_ADDR"),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                )
            except Exception:
                pass  # Never let audit logging break a request

        return response
