"""
apps/compliance/serializers.py
DRF serializers for compliance models.
"""

from __future__ import annotations

from rest_framework import serializers

from apps.compliance.models import (
    AuditTrail,
    ConsentRecord,
    GDPRRequest,
    KYCRecord,
)


class GDPRRequestSerializer(serializers.ModelSerializer):
    """Read-only GDPR request representation."""

    class Meta:
        model = GDPRRequest
        fields = [
            "id", "request_type", "status", "user_note",
            "rejection_reason", "export_ipfs_hash",
            "created_at", "due_by", "completed_at",
        ]
        read_only_fields = fields


class SubmitGDPRRequestSerializer(serializers.Serializer):
    """Input for submitting a new GDPR subject rights request."""

    request_type = serializers.ChoiceField(choices=GDPRRequest.RequestType.choices)
    user_note = serializers.CharField(
        max_length=2000,
        required=False,
        allow_blank=True,
        help_text="Optional context or reason for the request.",
    )


class RecordConsentSerializer(serializers.Serializer):
    """Input for recording or withdrawing consent."""

    purpose = serializers.ChoiceField(choices=ConsentRecord.Purpose.choices)
    given = serializers.BooleanField(help_text="True = consent, False = withdrawal")
    policy_version = serializers.CharField(max_length=20)


class ConsentRecordSerializer(serializers.ModelSerializer):
    """Consent record representation."""

    class Meta:
        model = ConsentRecord
        fields = [
            "id", "purpose", "given", "policy_version",
            "created_at", "withdrawn_at",
        ]
        read_only_fields = fields


class AuditTrailSerializer(serializers.ModelSerializer):
    """Audit trail entry."""

    class Meta:
        model = AuditTrail
        fields = [
            "id", "category", "action", "resource_type",
            "resource_id", "details", "legal_basis", "created_at",
        ]
        read_only_fields = fields


class KYCRecordSerializer(serializers.ModelSerializer):
    """KYC record status (documents omitted)."""

    class Meta:
        model = KYCRecord
        fields = [
            "id", "status", "risk_level", "provider",
            "pep_check_passed", "sanctions_check_passed",
            "submitted_at", "reviewed_at", "expires_at",
            "rejection_reason",
        ]
        read_only_fields = fields


class SubmitKYCSerializer(serializers.Serializer):
    """Input for KYC document submission (IPFS hashes only)."""

    id_document_ipfs = serializers.CharField(
        max_length=200,
        required=False,
        allow_blank=True,
        help_text="IPFS CID of the encrypted government ID document.",
    )
    proof_of_address_ipfs = serializers.CharField(
        max_length=200,
        required=False,
        allow_blank=True,
        help_text="IPFS CID of the encrypted proof of address.",
    )
    selfie_ipfs = serializers.CharField(
        max_length=200,
        required=False,
        allow_blank=True,
        help_text="IPFS CID of the encrypted selfie.",
    )

    def validate(self, attrs: dict) -> dict:
        """At least one document must be provided."""
        if not any([
            attrs.get("id_document_ipfs"),
            attrs.get("proof_of_address_ipfs"),
            attrs.get("selfie_ipfs"),
        ]):
            raise serializers.ValidationError(
                "At least one document IPFS hash is required."
            )
        return attrs
