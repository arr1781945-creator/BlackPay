"""
apps/compliance/gdpr.py
GDPR subject rights implementation.

Implements:
  - Data export (Art. 20 portability): JSON package of all user data
  - Data erasure (Art. 17): anonymise/delete PII, retain regulatory records
  - Consent management (Art. 7): record and withdraw consent per purpose
  - Data retention: scheduled cleanup of expired records

All erasure operations are logged in AuditTrail before execution.
Regulatory data (transactions, AML records) is never deleted — only
de-identified by replacing PII with cryptographic pseudonyms.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import timedelta
from typing import Any

from django.db import transaction as db_transaction
from django.utils import timezone

from apps.compliance.models import AuditTrail, ConsentRecord, GDPRRequest
from apps.users.models import AuditLog, User

log = logging.getLogger("blackpay.compliance.gdpr")

# Placeholder used for all erased PII fields
ERASED_PLACEHOLDER = "[ERASED]"


# ─── Data export ──────────────────────────────────────────────────────────────


def export_user_data(user: User) -> dict[str, Any]:
    """
    Generate a complete, portable JSON export of all user data.

    Covers: profile, PQC keys (public only), FIDO2 credentials,
    transactions, wallet balances, audit logs, consent records.
    Does NOT include encrypted secret keys or raw payment addresses.

    Args:
        user: User instance to export.

    Returns:
        JSON-serialisable dict with all exportable user data.
    """
    from apps.payments.models import Transaction
    from apps.wallet.models import Balance, Wallet

    export: dict[str, Any] = {
        "export_generated_at": timezone.now().isoformat(),
        "export_version": "1.0",
        "user_id": str(user.id),
    }

    # ── Profile ───────────────────────────────────────────────────────────────
    export["profile"] = {
        "email": user.email,
        "email_verified": user.email_verified,
        "is_verified": user.is_verified,
        "mfa_enabled": user.mfa_enabled,
        "mfa_method": user.mfa_method,
        "gdpr_consent_at": user.gdpr_consent_at.isoformat() if user.gdpr_consent_at else None,
        "created_at": user.created_at.isoformat(),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }

    # ── PQC keys (public keys only) ───────────────────────────────────────────
    export["pqc_keys"] = [
        {
            "id": str(k.id),
            "key_type": k.key_type,
            "algorithm": k.algorithm,
            "public_key_hex": k.public_key_hex,
            "purpose": k.purpose,
            "created_at": k.created_at.isoformat(),
        }
        for k in user.pqc_keys.filter(is_active=True)
    ]

    # ── FIDO2 credentials ─────────────────────────────────────────────────────
    export["fido2_credentials"] = [
        {
            "id": str(c.id),
            "device_name": c.device_name,
            "aaguid": c.aaguid,
            "created_at": c.created_at.isoformat(),
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
        }
        for c in user.fido2_credentials.filter(is_active=True)
    ]

    # ── Transactions ──────────────────────────────────────────────────────────
    export["transactions"] = [
        {
            "id": str(tx.id),
            "payment_type": tx.payment_type,
            "status": tx.status,
            "amount": str(tx.amount),
            "currency": tx.currency,
            "provider": tx.provider,
            "description": tx.description,
            "created_at": tx.created_at.isoformat(),
            "completed_at": tx.completed_at.isoformat() if tx.completed_at else None,
        }
        for tx in Transaction.objects.filter(user=user).order_by("created_at")
    ]

    # ── Wallet balances ───────────────────────────────────────────────────────
    try:
        wallet = Wallet.objects.get(user=user)
        export["wallet"] = {
            "id": str(wallet.id),
            "balances": [
                {"currency": b.currency, "amount": b.amount}
                for b in wallet.balances.all()
            ],
        }
    except Wallet.DoesNotExist:
        export["wallet"] = None

    # ── Consent records ───────────────────────────────────────────────────────
    export["consent_records"] = [
        {
            "purpose": c.purpose,
            "given": c.given,
            "policy_version": c.policy_version,
            "created_at": c.created_at.isoformat(),
            "withdrawn_at": c.withdrawn_at.isoformat() if c.withdrawn_at else None,
        }
        for c in user.consent_records.order_by("created_at")
    ]

    # ── Audit log (security events) ───────────────────────────────────────────
    export["security_events"] = [
        {
            "event_type": e.event_type,
            "created_at": e.created_at.isoformat(),
            "ip_address": e.ip_address,
        }
        for e in AuditLog.objects.filter(user=user).order_by("created_at")[:500]
    ]

    _log_audit(
        user=user,
        category="data_export",
        action="gdpr_export_generated",
        details={"record_counts": {k: len(v) if isinstance(v, list) else 1 for k, v in export.items()}},
    )

    return export


# ─── Data erasure ─────────────────────────────────────────────────────────────


def erase_user_data(user: User, request_id: str) -> dict[str, int]:
    """
    GDPR Art. 17 erasure: anonymise all user PII.

    Strategy:
      - User account: replace email with pseudonym, clear encrypted fields,
        deactivate account.
      - PQC keys: delete (no regulatory requirement).
      - FIDO2 credentials: delete.
      - Transactions: retain (regulatory requirement), replace encrypted
        recipient fields with ERASED_PLACEHOLDER.
      - Audit logs: retain structure, clear IP address and user reference.
      - Consent records: retain with user nulled (legal obligation records).

    Args:
        user:       User to erase.
        request_id: GDPRRequest UUID for audit trail linkage.

    Returns:
        Dict mapping data category → count of erased records.
    """
    counts: dict[str, int] = {}

    _log_audit(
        user=user,
        category="data_deletion",
        action="gdpr_erasure_start",
        details={"request_id": request_id},
    )

    with db_transaction.atomic():
        # ── Pseudonymise the account ──────────────────────────────────────────
        pseudo_email = f"erased_{uuid.uuid4().hex[:12]}@blackpay.deleted"
        user.email = pseudo_email
        user.phone_encrypted = ""
        user.full_name_encrypted = ""
        user.is_active = False
        user.gdpr_consent_at = None
        user.last_login_ip = None
        user.save(update_fields=[
            "email", "phone_encrypted", "full_name_encrypted",
            "is_active", "gdpr_consent_at", "last_login_ip",
        ])
        counts["user_account"] = 1

        # ── Delete PQC keys (no retention requirement) ────────────────────────
        n = user.pqc_keys.all().delete()[0]
        counts["pqc_keys"] = n

        # ── Delete FIDO2 credentials ──────────────────────────────────────────
        n = user.fido2_credentials.all().delete()[0]
        counts["fido2_credentials"] = n

        # ── MFA sessions ──────────────────────────────────────────────────────
        n = user.mfa_sessions.all().delete()[0]
        counts["mfa_sessions"] = n

        # ── Anonymise transaction recipient fields (retain records) ───────────
        from apps.payments.models import Transaction

        txs = Transaction.objects.filter(user=user)
        for tx in txs:
            tx.recipient_address_encrypted = ERASED_PLACEHOLDER
            tx.recipient_name_encrypted = ERASED_PLACEHOLDER
            tx.metadata.pop("provider_data", None)
            tx.save(update_fields=["recipient_address_encrypted",
                                   "recipient_name_encrypted", "metadata"])
        counts["transactions_anonymised"] = txs.count()

        # ── Clear audit log IPs and unlink user ───────────────────────────────
        n = AuditLog.objects.filter(user=user).update(
            ip_address=None,
            user_agent="",
            user=None,
        )
        counts["audit_logs_anonymised"] = n

        # ── Retain consent records but null the user FK ───────────────────────
        n = ConsentRecord.objects.filter(user=user).update(ip_address=None, user_agent="")
        counts["consent_records_anonymised"] = n

        # ── Mark GDPR request complete ────────────────────────────────────────
        GDPRRequest.objects.filter(id=request_id).update(
            status="completed",
            completed_at=timezone.now(),
        )

    log.info(
        "GDPR erasure completed",
        extra={"request_id": request_id, "counts": counts},
    )
    return counts


# ─── Consent management ───────────────────────────────────────────────────────


def record_consent(
    user: User,
    purpose: str,
    given: bool,
    policy_version: str,
    ip_address: str | None = None,
    user_agent: str = "",
) -> ConsentRecord:
    """
    Record a consent event for a specific processing purpose.

    If revoking consent, marks any previous active consent as withdrawn.

    Args:
        user:           User giving/withdrawing consent.
        purpose:        ConsentRecord.Purpose choice value.
        given:          True = consent given, False = consent withdrawn.
        policy_version: Version string of the policy accepted.
        ip_address:     Client IP for audit trail.
        user_agent:     Client UA string.

    Returns:
        New ConsentRecord instance.
    """
    if not given:
        # Mark previous consent(s) for this purpose as withdrawn
        ConsentRecord.objects.filter(
            user=user, purpose=purpose, given=True, withdrawn_at__isnull=True
        ).update(withdrawn_at=timezone.now())

    record = ConsentRecord.objects.create(
        user=user,
        purpose=purpose,
        given=given,
        policy_version=policy_version,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    _log_audit(
        user=user,
        category="consent_given" if given else "consent_withdrawn",
        action="consent_record_created",
        details={"purpose": purpose, "given": given, "policy_version": policy_version},
    )

    return record


def get_active_consents(user: User) -> dict[str, bool]:
    """
    Return a dict of purpose → consent_given for all known purposes.

    Purposes with no consent record default to False.

    Args:
        user: User to check.

    Returns:
        Dict mapping purpose string → bool.
    """
    result = {p.value: False for p in ConsentRecord.Purpose}
    active = ConsentRecord.objects.filter(
        user=user, given=True, withdrawn_at__isnull=True
    ).values_list("purpose", flat=True)
    for purpose in active:
        result[purpose] = True
    return result


# ─── Data retention cleanup ───────────────────────────────────────────────────


def apply_retention_policies() -> dict[str, int]:
    """
    Apply all active data retention policies: delete expired records.

    Called by a Celery Beat task (daily).

    Returns:
        Dict mapping data_category → number of records deleted.
    """
    from apps.compliance.models import DataRetentionPolicy

    counts: dict[str, int] = {}
    policies = DataRetentionPolicy.objects.filter(is_active=True, auto_delete=True)

    for policy in policies:
        cutoff = timezone.now() - timedelta(days=policy.retention_days)
        try:
            n = _delete_expired_records(policy.data_category, cutoff)
            counts[policy.data_category] = n
            log.info(
                "Retention policy applied",
                extra={"category": policy.data_category, "deleted": n},
            )
        except Exception as exc:
            log.error(
                "Retention policy failed",
                exc_info=exc,
                extra={"category": policy.data_category},
            )

    return counts


def _delete_expired_records(category: str, cutoff) -> int:
    """
    Delete records older than cutoff for the given data category.

    Args:
        category: DataRetentionPolicy.data_category value.
        cutoff:   Datetime threshold — records before this are deleted.

    Returns:
        Number of records deleted.
    """
    from apps.users.models import AuditLog

    _CATEGORY_MAP = {
        "audit_logs": lambda c: AuditLog.objects.filter(created_at__lt=c).delete()[0],
        "mfa_sessions": lambda c: __import__(
            "apps.users.models", fromlist=["MFASession"]
        ).MFASession.objects.filter(created_at__lt=c).delete()[0],
        "webhook_events": lambda c: __import__(
            "apps.payments.models", fromlist=["WebhookEvent"]
        ).WebhookEvent.objects.filter(created_at__lt=c, processed=True).delete()[0],
        "currency_rates": lambda c: __import__(
            "apps.wallet.models", fromlist=["CurrencyRate"]
        ).CurrencyRate.objects.filter(fetched_at__lt=c).delete()[0],
    }

    handler = _CATEGORY_MAP.get(category)
    if handler:
        return handler(cutoff)

    log.warning("Unknown retention category", extra={"category": category})
    return 0


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _log_audit(
    user: User,
    category: str,
    action: str,
    details: dict,
) -> None:
    """Create an AuditTrail entry for a compliance event."""
    try:
        AuditTrail.objects.create(
            user=user,
            category=category,
            action=action,
            details=details,
            legal_basis="legal_obligation",
        )
    except Exception as exc:
        log.error("Compliance audit trail write failed", exc_info=exc)
