"""
apps/compliance/models.py
GDPR, AML/KYC, and data retention compliance models.

GDPRRequest — tracks erasure, export, and rectification requests.
AuditTrail  — immutable structured event log (pairs with AuditLog in users app).
DataRetention — policy records governing how long each data category is kept.
ConsentRecord — granular consent tracking per user per purpose.
KYCRecord     — AML/KYC verification status and document references.
"""

from __future__ import annotations

import uuid

from django.db import models

from apps.users.models import User


class GDPRRequest(models.Model):
    """
    A GDPR subject rights request (Art. 17 erasure, Art. 20 portability,
    Art. 16 rectification, Art. 21 objection).

    Requests are processed within 30 days per GDPR Art. 12(3).
    Completion is recorded and auditable.
    """

    class RequestType(models.TextChoices):
        ERASURE = "erasure", "Right to Erasure (Art. 17)"
        EXPORT = "export", "Data Portability (Art. 20)"
        RECTIFICATION = "rectification", "Rectification (Art. 16)"
        OBJECTION = "objection", "Right to Object (Art. 21)"
        RESTRICTION = "restriction", "Restriction of Processing (Art. 18)"

    class RequestStatus(models.TextChoices):
        PENDING = "pending", "Pending Review"
        IN_PROGRESS = "in_progress", "In Progress"
        COMPLETED = "completed", "Completed"
        REJECTED = "rejected", "Rejected"
        EXTENDED = "extended", "Extended (30+30 days)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="gdpr_requests")

    request_type = models.CharField(max_length=20, choices=RequestType.choices)
    status = models.CharField(
        max_length=15, choices=RequestStatus.choices, default=RequestStatus.PENDING
    )

    # User-provided reason / additional details
    user_note = models.TextField(blank=True)

    # Internal notes (not shared with user)
    internal_note = models.TextField(blank=True)

    # Rejection reason (shared with user if rejected)
    rejection_reason = models.TextField(blank=True)

    # Export file path (for portability requests)
    export_file_path = models.TextField(blank=True)
    export_ipfs_hash = models.CharField(max_length=200, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    due_by = models.DateTimeField(
        null=True,
        blank=True,
        help_text="GDPR deadline: 30 days from creation"
    )
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "bp_gdpr_requests"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["request_type", "status"]),
        ]

    def __str__(self) -> str:
        return f"<GDPRRequest {self.request_type} [{self.status}] user={self.user_id}>"


class AuditTrail(models.Model):
    """
    Structured, immutable audit trail for all data access and processing events.

    Complements AuditLog (security events) with data-processing records
    required for GDPR accountability (Art. 5(2)).

    Records are signed with the platform ML-DSA-65 key on creation.
    They must never be modified or deleted except via GDPR erasure
    (which replaces user-identifying fields with REDACTED).
    """

    class Category(models.TextChoices):
        DATA_ACCESS = "data_access", "Data Access"
        DATA_EXPORT = "data_export", "Data Export"
        DATA_DELETION = "data_deletion", "Data Deletion"
        DATA_PROCESSING = "data_processing", "Data Processing"
        CONSENT_GIVEN = "consent_given", "Consent Given"
        CONSENT_WITHDRAWN = "consent_withdrawn", "Consent Withdrawn"
        KYC_CHECK = "kyc_check", "KYC/AML Check"
        THIRD_PARTY_SHARE = "third_party_share", "Third Party Data Share"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="audit_trail_entries"
    )

    category = models.CharField(max_length=30, choices=Category.choices, db_index=True)

    # Structured event detail
    action = models.CharField(max_length=100)
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=100, blank=True)
    details = models.JSONField(default=dict)

    # Processing legal basis (GDPR Art. 6)
    legal_basis = models.CharField(
        max_length=30,
        choices=[
            ("consent", "Consent (Art. 6(1)(a))"),
            ("contract", "Contract (Art. 6(1)(b))"),
            ("legal_obligation", "Legal Obligation (Art. 6(1)(c))"),
            ("vital_interests", "Vital Interests (Art. 6(1)(d))"),
            ("public_task", "Public Task (Art. 6(1)(e))"),
            ("legitimate_interests", "Legitimate Interests (Art. 6(1)(f))"),
        ],
        default="contract",
    )

    # Context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Integrity
    signature_hex = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "bp_audit_trail"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "category"]),
            models.Index(fields=["category", "created_at"]),
        ]


class DataRetentionPolicy(models.Model):
    """
    Data retention policy for a category of personal data.

    Defines how long each type of data must be retained (legal obligation)
    and when it should be auto-deleted (after retention period expires).

    Retention periods are governed by OJK and BI regulations for Indonesia,
    plus GDPR requirements for EU-related data.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    data_category = models.CharField(
        max_length=60,
        unique=True,
        help_text="E.g. 'transaction_records', 'kyc_documents', 'audit_logs'"
    )

    retention_days = models.PositiveIntegerField(
        help_text="Number of days to retain data after collection"
    )

    legal_basis = models.TextField(
        help_text="Citation of the law requiring this retention period"
    )

    auto_delete = models.BooleanField(
        default=False,
        help_text="If True, data is automatically deleted after retention_days"
    )

    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.EmailField(blank=True)

    class Meta:
        db_table = "bp_data_retention_policies"

    def __str__(self) -> str:
        return f"<RetentionPolicy {self.data_category} {self.retention_days}d>"


class ConsentRecord(models.Model):
    """
    Granular consent record per user per processing purpose.

    Records when consent was given, withdrawn, and the exact version
    of the privacy policy / terms accepted.  Required for GDPR Art. 7.
    """

    class Purpose(models.TextChoices):
        PAYMENT_PROCESSING = "payment_processing", "Payment Processing"
        ANALYTICS = "analytics", "Analytics"
        MARKETING = "marketing", "Marketing Communications"
        KYC_AML = "kyc_aml", "KYC/AML Checks"
        THIRD_PARTY_SHARING = "third_party_sharing", "Third Party Data Sharing"
        PROFILING = "profiling", "Automated Decision Making"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="consent_records")

    purpose = models.CharField(max_length=30, choices=Purpose.choices)
    given = models.BooleanField()
    policy_version = models.CharField(max_length=20, help_text="Privacy policy version accepted")

    # Context at time of consent
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "bp_consent_records"
        indexes = [
            models.Index(fields=["user", "purpose"]),
            models.Index(fields=["purpose", "given"]),
        ]


class KYCRecord(models.Model):
    """
    AML/KYC verification record for a user.

    Stores verification status, risk level, and document references.
    Document hashes are stored — actual documents live in encrypted IPFS.
    Compliant with OJK POJK No. 12/POJK.01/2017 and BI regulations.
    """

    class VerificationStatus(models.TextChoices):
        NOT_STARTED = "not_started", "Not Started"
        PENDING = "pending", "Pending Review"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        EXPIRED = "expired", "Expired (re-verification required)"

    class RiskLevel(models.TextChoices):
        LOW = "low", "Low Risk"
        MEDIUM = "medium", "Medium Risk"
        HIGH = "high", "High Risk"
        PROHIBITED = "prohibited", "Prohibited"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="kyc_record")

    status = models.CharField(
        max_length=15,
        choices=VerificationStatus.choices,
        default=VerificationStatus.NOT_STARTED,
        db_index=True,
    )
    risk_level = models.CharField(
        max_length=12,
        choices=RiskLevel.choices,
        default=RiskLevel.LOW,
    )

    # Document references (IPFS hashes of encrypted documents)
    id_document_ipfs = models.CharField(max_length=200, blank=True)
    proof_of_address_ipfs = models.CharField(max_length=200, blank=True)
    selfie_ipfs = models.CharField(max_length=200, blank=True)

    # Verification provider reference
    provider = models.CharField(max_length=40, blank=True, help_text="e.g. 'veriff', 'sumsub'")
    provider_ref = models.CharField(max_length=200, blank=True)

    # Reviewer notes
    reviewer_note = models.TextField(blank=True)
    rejection_reason = models.TextField(blank=True)

    # PEP/sanctions screening
    pep_check_passed = models.BooleanField(null=True, blank=True)
    sanctions_check_passed = models.BooleanField(null=True, blank=True)

    submitted_at = models.DateTimeField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bp_kyc_records"
        indexes = [models.Index(fields=["status", "risk_level"])]

    def __str__(self) -> str:
        return f"<KYCRecord user={self.user_id} status={self.status}>"
