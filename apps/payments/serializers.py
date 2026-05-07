"""
apps/payments/serializers.py
DRF serializers for Transaction, CryptoPayment, and FiatPayment.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

from rest_framework import serializers

from apps.payments.models import CryptoPayment, FiatPayment, Transaction, WebhookEvent


class CryptoPaymentSerializer(serializers.ModelSerializer):
    """Read-only crypto payment detail (address omitted — encrypted)."""

    class Meta:
        model = CryptoPayment
        fields = [
            "id", "coin", "network", "tx_hash", "confirmations",
            "required_confirmations", "nowpayments_payment_id",
            "pay_amount", "created_at",
        ]
        read_only_fields = fields


class FiatPaymentSerializer(serializers.ModelSerializer):
    """Read-only fiat payment detail (bank account omitted — encrypted)."""

    class Meta:
        model = FiatPayment
        fields = [
            "id", "method", "stripe_payment_intent_id", "wise_transfer_id",
            "exchange_rate", "fee_amount", "fee_currency", "created_at",
        ]
        read_only_fields = fields


class TransactionSerializer(serializers.ModelSerializer):
    """Full transaction with nested payment detail."""

    crypto_payment = CryptoPaymentSerializer(read_only=True)
    fiat_payment = FiatPaymentSerializer(read_only=True)

    class Meta:
        model = Transaction
        fields = [
            "id", "payment_type", "status", "amount", "currency", "amount_usd",
            "provider", "provider_tx_id", "description", "metadata",
            "zk_balance_proof", "error_message",
            "crypto_payment", "fiat_payment",
            "created_at", "updated_at", "completed_at",
        ]
        read_only_fields = fields


class CreateCryptoPaymentSerializer(serializers.Serializer):
    """
    Initiate a new cryptocurrency payment via NOWPayments or Transak.
    """

    amount = serializers.DecimalField(max_digits=36, decimal_places=18, min_value=Decimal("0.000001"))
    currency = serializers.CharField(max_length=10)
    pay_currency = serializers.CharField(max_length=10, help_text="Currency to pay in (e.g. BTC)")
    recipient_address = serializers.CharField(max_length=200, required=False, allow_blank=True)
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)
    provider = serializers.ChoiceField(
        choices=["nowpayments", "transak"],
        default="nowpayments",
    )
    include_zk_proof = serializers.BooleanField(
        default=False,
        help_text="Generate ZK balance proof and include in transaction",
    )

    def validate_currency(self, value: str) -> str:
        return value.upper()

    def validate_pay_currency(self, value: str) -> str:
        return value.upper()


class CreateFiatPaymentSerializer(serializers.Serializer):
    """
    Initiate a new fiat payment via Stripe or Wise.
    """

    amount = serializers.DecimalField(max_digits=20, decimal_places=8, min_value=Decimal("0.01"))
    currency = serializers.CharField(max_length=3)
    method = serializers.ChoiceField(choices=FiatPayment.Method.choices)
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)

    # Stripe card fields
    stripe_payment_method_id = serializers.CharField(required=False, allow_blank=True)

    # Wise fields
    wise_target_account_id = serializers.CharField(required=False, allow_blank=True)
    wise_target_currency = serializers.CharField(max_length=3, required=False, allow_blank=True)

    def validate_currency(self, value: str) -> str:
        return value.upper()


class WebhookEventSerializer(serializers.ModelSerializer):
    """Internal admin serializer for webhook events."""

    class Meta:
        model = WebhookEvent
        fields = "__all__"
        read_only_fields = fields
