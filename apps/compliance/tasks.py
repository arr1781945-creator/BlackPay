"""
apps/compliance/tasks.py
Celery tasks for GDPR processing and data retention.
"""

from __future__ import annotations

import json
import logging

from celery import shared_task
from django.utils import timezone

log = logging.getLogger("blackpay.compliance.tasks")


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="compliance",
    name="compliance.process_gdpr_export",
)
def process_gdpr_export(self, gdpr_request_id: str) -> dict:
    """
    Generate and store a GDPR data export for the given request.

    Stores the JSON export in IPFS and records the CID on the request.

    Args:
        gdpr_request_id: GDPRRequest UUID string.
    """
    from apps.compliance.gdpr import export_user_data
    from apps.compliance.models import GDPRRequest
    from apps.ipfs_storage.ipfs_client import IPFSClient

    try:
        req = GDPRRequest.objects.select_related("user").get(id=gdpr_request_id)
    except GDPRRequest.DoesNotExist:
        return {"error": "request_not_found"}

    req.status = "in_progress"
    req.save(update_fields=["status"])

    try:
        export_data = export_user_data(req.user)
        export_json = json.dumps(export_data, indent=2, ensure_ascii=False)

        # Store in IPFS
        ipfs = IPFSClient()
        cid = ipfs.add_json(export_data)

        req.export_ipfs_hash = cid
        req.status = "completed"
        req.completed_at = timezone.now()
        req.save(update_fields=["export_ipfs_hash", "status", "completed_at"])

        log.info("GDPR export completed", extra={"request_id": gdpr_request_id, "cid": cid})
        return {"status": "completed", "ipfs_cid": cid}

    except Exception as exc:
        log.error("GDPR export failed", exc_info=exc)
        req.status = "pending"
        req.internal_note = str(exc)
        req.save(update_fields=["status", "internal_note"])
        raise self.retry(exc=exc)


@shared_task(
    bind=True,
    max_retries=2,
    default_retry_delay=300,
    queue="compliance",
    name="compliance.process_gdpr_erasure",
)
def process_gdpr_erasure(self, gdpr_request_id: str) -> dict:
    """
    Execute a GDPR erasure request.

    Anonymises all PII for the user. This is irreversible.

    Args:
        gdpr_request_id: GDPRRequest UUID string.
    """
    from apps.compliance.gdpr import erase_user_data
    from apps.compliance.models import GDPRRequest

    try:
        req = GDPRRequest.objects.select_related("user").get(id=gdpr_request_id)
    except GDPRRequest.DoesNotExist:
        return {"error": "request_not_found"}

    if req.status == "completed":
        return {"status": "already_completed"}

    req.status = "in_progress"
    req.save(update_fields=["status"])

    try:
        counts = erase_user_data(req.user, gdpr_request_id)
        log.info("GDPR erasure completed", extra={"request_id": gdpr_request_id, "counts": counts})
        return {"status": "completed", "counts": counts}

    except Exception as exc:
        log.error("GDPR erasure failed", exc_info=exc)
        raise self.retry(exc=exc)


@shared_task(
    name="compliance.apply_retention_policies",
    queue="maintenance",
)
def apply_retention_policies_task() -> dict:
    """
    Periodic task: apply all active data retention policies.
    Scheduled daily via Celery Beat.
    """
    from apps.compliance.gdpr import apply_retention_policies

    counts = apply_retention_policies()
    log.info("Retention policies applied", extra={"counts": counts})
    return counts
