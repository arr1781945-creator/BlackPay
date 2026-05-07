"""
apps/payments/tasks.py
Celery async tasks for payment processing.

Tasks:
  - poll_crypto_payment_status  — Poll NOWPayments for payment confirmation
  - process_stripe_webhook      — Handle Stripe webhook events
  - process_nowpayments_ipn     — Handle NOWPayments IPN events
  - process_transak_webhook     — Handle Transak webhook events
  - finalize_transaction        — Update transaction status and notify user
  - retry_failed_payment        — Retry failed payment with backoff
  - expire_pending_transactions — Mark stale pending payments as expired
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

from celery import shared_task
from django.db import transaction
from django.utils import timezone

log = logging.getLogger("blackpay.payments.tasks")

# ─── Constants ────────────────────────────────────────────────────────────────

MAX_POLL_ATTEMPTS = 48          # 48 × 5 min = 4 hours max wait
POLL_INTERVAL_SECONDS = 300     # 5 minutes
PAYMENT_EXPIRY_HOURS = 4        # pending payments expire after 4 hours


# ─── NOWPayments ──────────────────────────────────────────────────────────────


@shared_task(
    bind=True,
    max_retries=MAX_POLL_ATTEMPTS,
    default_retry_delay=POLL_INTERVAL_SECONDS,
    queue="payments",
    name="payments.poll_crypto_payment_status",
)
def poll_crypto_payment_status(self, transaction_id: str) -> dict:
    """
    Poll NOWPayments for the current status of a crypto payment.

    Re-queues itself every POLL_INTERVAL_SECONDS until the payment
    reaches a terminal state (finished, failed, expired, refunded).

    Args:
        transaction_id: BlackPay Transaction UUID string.

    Returns:
        Dict with 'status' and 'payment_status' from NOWPayments.
    """
    from apps.payments.models import CryptoPayment, Transaction
    from apps.payments.nowpayments import NOWPaymentsClient

    try:
        tx = Transaction.objects.select_related("crypto_payment").get(id=transaction_id)
    except Transaction.DoesNotExist:
        log.error("poll_crypto_payment_status: tx not found", extra={"id": transaction_id})
        return {"error": "transaction_not_found"}

    cp: Optional[CryptoPayment] = getattr(tx, "crypto_payment", None)
    if not cp or not cp.nowpayments_payment_id:
        log.warning("No NOWPayments payment ID on transaction", extra={"tx": transaction_id})
        return {"error": "no_payment_id"}

    client = NOWPaymentsClient()
    try:
        data = client.get_payment_status(cp.nowpayments_payment_id)
    except Exception as exc:
        log.warning(
            "NOWPayments poll failed, retrying",
            exc_info=exc,
            extra={"tx": transaction_id},
        )
        raise self.retry(exc=exc)

    payment_status = data.get("payment_status", "")
    log.info(
        "NOWPayments poll",
        extra={"tx": transaction_id, "np_status": payment_status},
    )

    terminal_states = {"finished", "failed", "expired", "refunded", "partially_paid"}
    if payment_status not in terminal_states:
        # Not done yet — retry
        raise self.retry(countdown=POLL_INTERVAL_SECONDS)

    # Update confirmations
    cp.confirmations = data.get("actually_paid_amount", 0) and 1 or 0
    cp.tx_hash = data.get("outcome_tx_id") or data.get("tx_id") or ""
    cp.save(update_fields=["confirmations", "tx_hash"])

    # Map NOWPayments terminal status → BlackPay status
    _NOW_STATUS_MAP = {
        "finished": "completed",
        "failed": "failed",
        "expired": "failed",
        "refunded": "refunded",
        "partially_paid": "failed",
    }
    bp_status = _NOW_STATUS_MAP.get(payment_status, "failed")

    finalize_transaction.delay(transaction_id, bp_status, data)
    return {"status": bp_status, "payment_status": payment_status}


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="payments",
    name="payments.process_nowpayments_ipn",
)
def process_nowpayments_ipn(self, webhook_event_id: str) -> dict:
    """
    Process a verified NOWPayments IPN webhook event.

    Args:
        webhook_event_id: WebhookEvent UUID string.

    Returns:
        Dict with processing result.
    """
    from apps.payments.models import CryptoPayment, Transaction, WebhookEvent

    try:
        event = WebhookEvent.objects.select_related("related_transaction").get(
            id=webhook_event_id
        )
    except WebhookEvent.DoesNotExist:
        return {"error": "webhook_event_not_found"}

    payload = event.payload
    nowpayments_id = str(payload.get("payment_id", ""))
    payment_status = payload.get("payment_status", "")

    try:
        cp = CryptoPayment.objects.select_related("transaction").get(
            nowpayments_payment_id=nowpayments_id
        )
    except CryptoPayment.DoesNotExist:
        log.warning("IPN for unknown NOWPayments ID", extra={"np_id": nowpayments_id})
        event.error_message = "No CryptoPayment found for payment_id"
        event.save(update_fields=["error_message"])
        return {"error": "not_found"}

    tx = cp.transaction
    event.related_transaction = tx
    event.signature_valid = True
    event.save(update_fields=["related_transaction", "signature_valid"])

    _NOW_STATUS_MAP = {
        "finished": "completed",
        "failed": "failed",
        "expired": "failed",
        "refunded": "refunded",
    }
    bp_status = _NOW_STATUS_MAP.get(payment_status)

    if bp_status and tx.status == "pending":
        finalize_transaction.delay(str(tx.id), bp_status, payload)

    event.processed = True
    event.processed_at = timezone.now()
    event.save(update_fields=["processed", "processed_at"])

    return {"status": bp_status, "tx_id": str(tx.id)}


# ─── Stripe ───────────────────────────────────────────────────────────────────


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    queue="payments",
    name="payments.process_stripe_webhook",
)
def process_stripe_webhook(self, webhook_event_id: str) -> dict:
    """
    Process a verified Stripe webhook event.

    Handles:
      - payment_intent.succeeded   → complete transaction
      - payment_intent.failed      → fail transaction
      - charge.refunded            → refund transaction
      - payment_intent.canceled    → cancel transaction

    Args:
        webhook_event_id: WebhookEvent UUID string.

    Returns:
        Dict with processing result.
    """
    from apps.payments.models import FiatPayment, Transaction, WebhookEvent

    try:
        event = WebhookEvent.objects.get(id=webhook_event_id)
    except WebhookEvent.DoesNotExist:
        return {"error": "event_not_found"}

    payload = event.payload
    event_type = event.event_type
    stripe_obj = payload.get("data", {}).get("object", {})
    payment_intent_id = stripe_obj.get("id", "")

    # Resolve to a BlackPay FiatPayment + Transaction
    try:
        fp = FiatPayment.objects.select_related("transaction").get(
            stripe_payment_intent_id=payment_intent_id
        )
    except FiatPayment.DoesNotExist:
        log.warning(
            "Stripe webhook: no FiatPayment for PI",
            extra={"pi_id": payment_intent_id, "event_type": event_type},
        )
        event.processed = True
        event.processed_at = timezone.now()
        event.save(update_fields=["processed", "processed_at"])
        return {"error": "not_found"}

    tx = fp.transaction
    event.related_transaction = tx
    event.save(update_fields=["related_transaction"])

    _STRIPE_STATUS_MAP = {
        "payment_intent.succeeded": "completed",
        "payment_intent.payment_failed": "failed",
        "payment_intent.canceled": "cancelled",
        "charge.refunded": "refunded",
    }
    bp_status = _STRIPE_STATUS_MAP.get(event_type)

    if bp_status:
        finalize_transaction.delay(str(tx.id), bp_status, payload)

    # Store charge ID if present
    if event_type == "payment_intent.succeeded":
        charges = stripe_obj.get("charges", {}).get("data", [])
        if charges:
            fp.stripe_charge_id = charges[0].get("id", "")
            fp.save(update_fields=["stripe_charge_id"])

    event.processed = True
    event.processed_at = timezone.now()
    event.save(update_fields=["processed", "processed_at"])

    return {"status": bp_status, "tx_id": str(tx.id)}


# ─── Transak ─────────────────────────────────────────────────────────────────


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    queue="payments",
    name="payments.process_transak_webhook",
)
def process_transak_webhook(self, webhook_event_id: str) -> dict:
    """
    Process a verified Transak webhook event.

    Args:
        webhook_event_id: WebhookEvent UUID string.

    Returns:
        Dict with processing result.
    """
    from apps.payments.models import CryptoPayment, Transaction, WebhookEvent

    try:
        event = WebhookEvent.objects.get(id=webhook_event_id)
    except WebhookEvent.DoesNotExist:
        return {"error": "event_not_found"}

    order_data = event.payload.get("data", {})
    transak_order_id = order_data.get("id", "")
    transak_status = order_data.get("status", "")

    try:
        cp = CryptoPayment.objects.select_related("transaction").get(
            transak_order_id=transak_order_id
        )
    except CryptoPayment.DoesNotExist:
        log.warning("Transak webhook: order not found", extra={"order_id": transak_order_id})
        event.processed = True
        event.processed_at = timezone.now()
        event.save(update_fields=["processed", "processed_at"])
        return {"error": "not_found"}

    tx = cp.transaction
    event.related_transaction = tx

    _TRANSAK_STATUS_MAP = {
        "COMPLETED": "completed",
        "FAILED": "failed",
        "CANCELLED": "cancelled",
        "REFUNDED": "refunded",
    }
    bp_status = _TRANSAK_STATUS_MAP.get(transak_status.upper())

    if bp_status:
        finalize_transaction.delay(str(tx.id), bp_status, order_data)

    event.processed = True
    event.processed_at = timezone.now()
    event.save(update_fields=["related_transaction", "processed", "processed_at"])

    return {"status": bp_status, "tx_id": str(tx.id)}


# ─── Finalization ─────────────────────────────────────────────────────────────


@shared_task(
    bind=True,
    max_retries=5,
    default_retry_delay=10,
    queue="payments",
    name="payments.finalize_transaction",
)
def finalize_transaction(
    self,
    transaction_id: str,
    new_status: str,
    provider_data: dict,
) -> dict:
    """
    Atomically update a transaction's status and emit an audit log entry.

    Uses SELECT FOR UPDATE to prevent race conditions from concurrent webhooks.

    Args:
        transaction_id: BlackPay Transaction UUID.
        new_status:     Target status: completed, failed, refunded, or cancelled.
        provider_data:  Raw provider response for audit purposes.

    Returns:
        Dict with 'transaction_id' and 'status'.
    """
    from apps.payments.models import Transaction
    from apps.users.pqc_auth import create_audit_log

    try:
        with transaction.atomic():
            tx = (
                Transaction.objects.select_for_update()
                .get(id=transaction_id)
            )
            # Idempotency guard — don't re-process terminal states
            if tx.status in ("completed", "refunded", "cancelled"):
                log.info(
                    "finalize_transaction: already terminal",
                    extra={"tx": transaction_id, "status": tx.status},
                )
                return {"transaction_id": transaction_id, "status": tx.status}

            tx.status = new_status
            if new_status == "completed":
                tx.completed_at = timezone.now()
            tx.metadata["provider_data"] = provider_data
            tx.save(update_fields=["status", "completed_at", "metadata"])

        log.info(
            "Transaction finalized",
            extra={"tx": transaction_id, "status": new_status},
        )

        # Emit audit entry
        create_audit_log(
            event_type=(
                "transaction_completed" if new_status == "completed"
                else "transaction_failed"
            ),
            user=None,
            details={"transaction_id": transaction_id, "status": new_status},
        )

        # Notify user via wallet balance update
        if new_status == "completed":
            update_wallet_balance.delay(transaction_id)

        return {"transaction_id": transaction_id, "status": new_status}

    except Transaction.DoesNotExist:
        log.error("finalize_transaction: tx not found", extra={"id": transaction_id})
        return {"error": "not_found"}
    except Exception as exc:
        log.error("finalize_transaction failed", exc_info=exc)
        raise self.retry(exc=exc)


# ─── Wallet balance ───────────────────────────────────────────────────────────


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=5,
    queue="wallet",
    name="payments.update_wallet_balance",
)
def update_wallet_balance(self, transaction_id: str) -> dict:
    """
    Update the user's wallet balance after a completed transaction.

    Args:
        transaction_id: Completed Transaction UUID.

    Returns:
        Dict with updated balance info.
    """
    from apps.payments.models import Transaction
    from apps.wallet.models import Balance, Wallet

    try:
        tx = Transaction.objects.get(id=transaction_id, status="completed")
    except Transaction.DoesNotExist:
        log.warning("update_wallet_balance: tx not found or not complete", extra={"id": transaction_id})
        return {"error": "not_found"}

    try:
        with transaction.atomic():
            wallet, _ = Wallet.objects.get_or_create(user=tx.user)
            balance, _ = Balance.objects.select_for_update().get_or_create(
                wallet=wallet,
                currency=tx.currency,
                defaults={"amount": "0"},
            )
            balance.amount = str(
                round(float(balance.amount or 0) + float(tx.amount), 18)
            )
            balance.save(update_fields=["amount"])

        log.info(
            "Wallet balance updated",
            extra={"user": str(tx.user_id), "currency": tx.currency, "amount": str(tx.amount)},
        )
        return {"currency": tx.currency, "balance": balance.amount}

    except Exception as exc:
        log.error("update_wallet_balance failed", exc_info=exc)
        raise self.retry(exc=exc)


# ─── Maintenance ──────────────────────────────────────────────────────────────


@shared_task(
    name="payments.expire_pending_transactions",
    queue="maintenance",
)
def expire_pending_transactions() -> dict:
    """
    Periodic task: mark stale pending transactions as failed.

    Should be scheduled via Celery Beat every hour.
    Transactions older than PAYMENT_EXPIRY_HOURS with status 'pending'
    are marked 'failed' with a descriptive error message.

    Returns:
        Dict with 'expired_count'.
    """
    from apps.payments.models import Transaction

    cutoff = timezone.now() - timedelta(hours=PAYMENT_EXPIRY_HOURS)
    expired = Transaction.objects.filter(
        status="pending",
        created_at__lt=cutoff,
    )
    count = expired.update(
        status="failed",
        error_message=f"Payment expired after {PAYMENT_EXPIRY_HOURS} hours",
    )
    log.info("Expired pending transactions", extra={"count": count})
    return {"expired_count": count}
