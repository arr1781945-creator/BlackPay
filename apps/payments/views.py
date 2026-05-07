"""
apps/payments/views.py
Payment API views: create payments, retrieve status, handle webhooks.

All create endpoints require JWT authentication + MFA.
Webhook endpoints are public but signature-verified before any processing.
"""

from __future__ import annotations

import logging
from decimal import Decimal

from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.payments.models import Transaction, WebhookEvent
from apps.payments.serializers import (
    CreateCryptoPaymentSerializer,
    CreateFiatPaymentSerializer,
    TransactionSerializer,
)
from apps.payments.tasks import (
    poll_crypto_payment_status,
    process_nowpayments_ipn,
    process_stripe_webhook,
    process_transak_webhook,
)
from apps.users.pqc_auth import create_audit_log

log = logging.getLogger("blackpay.payments.views")


# ─── Crypto payments ──────────────────────────────────────────────────────────


class CreateCryptoPaymentView(APIView):
    """
    POST /api/v1/payments/crypto/create/
    Initiate a new cryptocurrency payment via NOWPayments or Transak.

    Optionally generates a ZK balance proof if include_zk_proof=True.
    Queues a Celery polling task to track payment confirmation.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Create a new crypto payment transaction."""
        serializer = CreateCryptoPaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        provider = d["provider"]

        # Optional ZK balance proof
        zk_proof_b64 = ""
        if d.get("include_zk_proof"):
            zk_proof_b64 = self._generate_zk_proof(request.user, d["amount"], d["currency"])

        # Create the Transaction record
        tx = Transaction.objects.create(
            user=request.user,
            tenant_id=request.user.tenant_id,
            payment_type="crypto",
            status="pending",
            amount=d["amount"],
            currency=d["currency"],
            provider=provider,
            description=d.get("description", ""),
            zk_balance_proof=zk_proof_b64,
        )

        if d.get("recipient_address"):
            tx.set_recipient_address(d["recipient_address"])
            tx.save(update_fields=["recipient_address_encrypted"])

        # Dispatch to payment provider
        if provider == "nowpayments":
            response_data = self._create_nowpayments(tx, d)
        else:
            response_data = self._create_transak(tx, d)

        create_audit_log(
            "transaction_created",
            request.user,
            {"tx_id": str(tx.id), "amount": str(d["amount"]), "currency": d["currency"]},
            request,
        )

        return Response(
            {
                "transaction_id": str(tx.id),
                "status": tx.status,
                **response_data,
            },
            status=status.HTTP_201_CREATED,
        )

    def _create_nowpayments(self, tx: Transaction, d: dict) -> dict:
        """Create a NOWPayments invoice and persist the CryptoPayment."""
        from apps.payments.models import CryptoPayment
        from apps.payments.nowpayments import NOWPaymentsClient

        client = NOWPaymentsClient()
        try:
            payment = client.create_payment(
                price_amount=d["amount"],
                price_currency=d["currency"],
                pay_currency=d["pay_currency"],
                order_id=str(tx.id),
                order_description=d.get("description", "BlackPay payment"),
            )
        except Exception as exc:
            tx.status = "failed"
            tx.error_message = str(exc)
            tx.save(update_fields=["status", "error_message"])
            raise

        cp = CryptoPayment(
            transaction=tx,
            coin=d["pay_currency"],
            nowpayments_payment_id=str(payment["payment_id"]),
            pay_amount=Decimal(str(payment.get("pay_amount", 0))),
        )
        cp.set_pay_address(payment.get("pay_address", ""))
        cp.save()

        tx.provider_tx_id = str(payment["payment_id"])
        tx.save(update_fields=["provider_tx_id"])

        # Start polling
        poll_crypto_payment_status.apply_async(
            args=[str(tx.id)],
            countdown=60,
        )

        return {
            "provider": "nowpayments",
            "pay_address": payment.get("pay_address"),
            "pay_amount": payment.get("pay_amount"),
            "pay_currency": payment.get("pay_currency"),
            "payment_id": payment["payment_id"],
        }

    def _create_transak(self, tx: Transaction, d: dict) -> dict:
        """Generate a Transak checkout URL and persist the CryptoPayment."""
        from apps.payments.models import CryptoPayment
        from apps.payments.transak_client import TransakClient

        client = TransakClient()
        checkout_url = client.generate_checkout_url(
            crypto_currency=d["pay_currency"],
            fiat_currency=d["currency"],
            fiat_amount=float(d["amount"]),
            partner_order_id=str(tx.id),
            wallet_address=tx.get_recipient_address() or None,
        )

        cp = CryptoPayment.objects.create(
            transaction=tx,
            coin=d["pay_currency"],
            transak_order_id=str(tx.id),
        )

        return {
            "provider": "transak",
            "checkout_url": checkout_url,
        }

    def _generate_zk_proof(self, user, amount: Decimal, currency: str) -> str:
        """
        Generate a ZK sufficient-balance proof for the given amount.

        Returns base64-encoded proof string, or empty string on failure.
        """
        try:
            from apps.zk_layer.zk_proof import generate_balance_proof

            return generate_balance_proof(user, amount, currency)
        except Exception as exc:
            log.warning("ZK proof generation failed (non-fatal)", exc_info=exc)
            return ""


# ─── Fiat payments ────────────────────────────────────────────────────────────


class CreateFiatPaymentView(APIView):
    """
    POST /api/v1/payments/fiat/create/
    Initiate a new fiat payment via Stripe or Wise.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Create a new fiat payment transaction."""
        serializer = CreateFiatPaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        method = d["method"]
        provider = "stripe" if "stripe" in method else "wise"

        tx = Transaction.objects.create(
            user=request.user,
            tenant_id=request.user.tenant_id,
            payment_type="fiat",
            status="pending",
            amount=d["amount"],
            currency=d["currency"],
            provider=provider,
            description=d.get("description", ""),
        )

        if provider == "stripe":
            response_data = self._create_stripe(tx, d)
        else:
            response_data = self._create_wise(tx, d)

        create_audit_log(
            "transaction_created",
            request.user,
            {"tx_id": str(tx.id), "method": method},
            request,
        )

        return Response(
            {"transaction_id": str(tx.id), "status": tx.status, **response_data},
            status=status.HTTP_201_CREATED,
        )

    def _create_stripe(self, tx: Transaction, d: dict) -> dict:
        """Create a Stripe PaymentIntent and persist FiatPayment."""
        from apps.payments.models import FiatPayment
        from apps.payments.stripe_client import create_payment_intent

        intent = create_payment_intent(
            amount=d["amount"],
            currency=d["currency"],
            payment_method_id=d.get("stripe_payment_method_id") or None,
            metadata={"blackpay_transaction_id": str(tx.id)},
            description=d.get("description", ""),
        )

        fp = FiatPayment.objects.create(
            transaction=tx,
            method=d["method"],
            stripe_payment_intent_id=intent.id,
        )

        tx.provider_tx_id = intent.id
        tx.save(update_fields=["provider_tx_id"])

        return {
            "provider": "stripe",
            "client_secret": intent.client_secret,
            "payment_intent_id": intent.id,
        }

    def _create_wise(self, tx: Transaction, d: dict) -> dict:
        """Create a Wise quote and return quote details for confirmation."""
        from apps.payments.models import FiatPayment
        from apps.payments.wise_client import WiseClient

        client = WiseClient()
        quote = client.create_quote(
            source_currency=d["currency"],
            target_currency=d.get("wise_target_currency", d["currency"]),
            source_amount=d["amount"],
        )

        fp = FiatPayment.objects.create(
            transaction=tx,
            method=d["method"],
            wise_quote_id=quote.get("id", ""),
            exchange_rate=Decimal(str(quote.get("rate", 0))),
        )

        return {
            "provider": "wise",
            "quote_id": quote.get("id"),
            "rate": quote.get("rate"),
            "fee": quote.get("fee"),
            "estimated_delivery": quote.get("estimatedDelivery"),
        }


# ─── Transaction list / detail ────────────────────────────────────────────────


class TransactionListView(generics.ListAPIView):
    """
    GET /api/v1/payments/transactions/
    List the current user's transactions, newest first.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TransactionSerializer

    def get_queryset(self):
        qs = Transaction.objects.filter(user=self.request.user).select_related(
            "crypto_payment", "fiat_payment"
        )
        status_filter = self.request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)
        return qs


class TransactionDetailView(generics.RetrieveAPIView):
    """
    GET /api/v1/payments/transactions/<pk>/
    Retrieve a single transaction's full details.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TransactionSerializer

    def get_queryset(self):
        return Transaction.objects.filter(user=self.request.user).select_related(
            "crypto_payment", "fiat_payment"
        )


# ─── Webhook endpoints (public, signature-verified) ───────────────────────────


class NOWPaymentsWebhookView(APIView):
    """
    POST /api/v1/payments/webhooks/nowpayments/
    Receive and verify NOWPayments IPN callbacks.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Verify IPN signature and enqueue processing task."""
        from apps.payments.nowpayments import NOWPaymentsClient

        client = NOWPaymentsClient()
        sig_header = request.META.get("HTTP_X_NOWPAYMENTS_SIG", "")
        payload = request.data

        is_valid = client.verify_ipn_signature(payload, sig_header)

        event = WebhookEvent.objects.create(
            provider="nowpayments",
            event_type=payload.get("payment_status", "unknown"),
            provider_event_id=str(payload.get("payment_id", "")),
            payload=payload,
            raw_body=request.body.decode("utf-8", errors="replace"),
            signature_valid=is_valid,
        )

        if not is_valid:
            log.warning("NOWPayments IPN signature invalid", extra={"event_id": str(event.id)})
            return Response({"detail": "Invalid signature."}, status=status.HTTP_400_BAD_REQUEST)

        process_nowpayments_ipn.delay(str(event.id))
        return Response({"received": True})


class StripeWebhookView(APIView):
    """
    POST /api/v1/payments/webhooks/stripe/
    Receive and verify Stripe webhook events.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Verify Stripe-Signature and enqueue processing task."""
        from apps.payments.stripe_client import verify_webhook_signature

        sig_header = request.META.get("HTTP_STRIPE_SIGNATURE", "")
        try:
            stripe_event = verify_webhook_signature(request.body, sig_header)
            is_valid = True
        except Exception as exc:
            log.warning("Stripe webhook verification failed", exc_info=exc)
            is_valid = False
            stripe_event = None

        payload = request.data
        event = WebhookEvent.objects.create(
            provider="stripe",
            event_type=payload.get("type", "unknown"),
            provider_event_id=payload.get("id", ""),
            payload=payload,
            raw_body=request.body.decode("utf-8", errors="replace"),
            signature_valid=is_valid,
        )

        if not is_valid:
            return Response({"detail": "Invalid signature."}, status=status.HTTP_400_BAD_REQUEST)

        process_stripe_webhook.delay(str(event.id))
        return Response({"received": True})


class TransakWebhookView(APIView):
    """
    POST /api/v1/payments/webhooks/transak/
    Receive and verify Transak webhook events.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        """Verify X-TRANSAK-SIGNATURE and enqueue processing task."""
        from apps.payments.transak_client import TransakClient

        client = TransakClient()
        sig_header = request.META.get("HTTP_X_TRANSAK_SIGNATURE", "")
        is_valid = client.verify_webhook_signature(request.body, sig_header)

        payload = request.data
        event = WebhookEvent.objects.create(
            provider="transak",
            event_type=payload.get("event_id", "unknown"),
            provider_event_id=payload.get("data", {}).get("id", ""),
            payload=payload,
            raw_body=request.body.decode("utf-8", errors="replace"),
            signature_valid=is_valid,
        )

        if not is_valid:
            return Response({"detail": "Invalid signature."}, status=status.HTTP_400_BAD_REQUEST)

        process_transak_webhook.delay(str(event.id))
        return Response({"received": True})
