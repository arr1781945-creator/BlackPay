"""
apps/payments/models.py
Transaction, CryptoPayment, FiatPayment, and WebhookEvent models.

All amounts are stored as Decimal strings to avoid float precision loss.
Sensitive fields (wallet addresses, account numbers) are AES-256-GCM encrypted.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.db import models

from apps.users.models import User


class Transaction(models.Model):
    """
    Top-level payment record representing a single BlackPay payment intent.

    A Transaction can have one CryptoPayment or FiatPayment child.
    Status transitions: pending → processing → completed / failed / refunded.
    Each status change is signed with the platform signing key.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        REFUNDED = "refunded", "Refunded"
        CANCELLED = "cancelled", "Cancelled"

    class PaymentType(models.TextChoices):
        CRYPTO = "crypto", "Cryptocurrency"
        FIAT = "fiat", "Fiat Currency"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.PROTECT, related_name="transactions")
    tenant_id = models.UUIDField(null=True, blank=True, db_index=True)

    payment_type = models.CharField(max_length=10, choices=PaymentType.choices)
    status = models.CharField(
        max_length=15, choices=Status.choices, default=Status.PENDING, db_index=True
    )

    # Amount and currency
    amount = models.DecimalField(max_digits=36, decimal_places=18)
    currency = models.CharField(max_length=10, db_index=True)
    amount_usd = models.DecimalField(max_digits=20, decimal_places=8, null=True, blank=True)

    # Destination (encrypted at rest)
    recipient_address_encrypted = models.TextField(blank=True)
    recipient_name_encrypted = models.TextField(blank=True)

    # Reference from payment provider
    provider = models.CharField(max_length=30, blank=True)
    provider_tx_id = models.CharField(max_length=200, blank=True, db_index=True)

    # ZK proof of sufficient balance (stored as base64)
    zk_balance_proof = models.TextField(blank=True)

    # ML-DSA-65 signature over the transaction details
    signature_hex = models.TextField(blank=True)

    # Metadata
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "bp_transactions"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["provider", "provider_tx_id"]),
        ]

    def __str__(self) -> str:
        return f"<Transaction {self.id} {self.amount} {self.currency} [{self.status}]>"

    def get_recipient_address(self) -> str:
        """Decrypt and return the recipient wallet address."""
        from apps.crypto_bridge.symmetric import decrypt_field, get_field_encryption_key

        if not self.recipient_address_encrypted:
            return ""
        fek = get_field_encryption_key()
        return decrypt_field(self.recipient_address_encrypted, fek, str(self.id).encode())

    def set_recipient_address(self, address: str) -> None:
        """Encrypt and store the recipient wallet address."""
        from apps.crypto_bridge.symmetric import encrypt_field, get_field_encryption_key

        fek = get_field_encryption_key()
        self.recipient_address_encrypted = encrypt_field(address, fek, str(self.id).encode())


class CryptoPayment(models.Model):
    """
    Cryptocurrency payment details for a Transaction.

    Supports all currencies provided by NOWPayments and Transak.
    Network confirmations and block data are tracked here.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.OneToOneField(
        Transaction, on_delete=models.CASCADE, related_name="crypto_payment"
    )

    # On-chain details
    coin = models.CharField(max_length=20, help_text="e.g. BTC, ETH, ZEC")
    network = models.CharField(max_length=30, blank=True, help_text="e.g. ERC20, BEP20")
    tx_hash = models.CharField(max_length=200, blank=True, db_index=True)
    confirmations = models.PositiveIntegerField(default=0)
    required_confirmations = models.PositiveIntegerField(default=1)

    # NOWPayments specific
    nowpayments_payment_id = models.CharField(max_length=100, blank=True, db_index=True)
    pay_address_encrypted = models.TextField(blank=True)
    pay_amount = models.DecimalField(max_digits=36, decimal_places=18, null=True, blank=True)

    # Transak specific
    transak_order_id = models.CharField(max_length=100, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bp_crypto_payments"

    def get_pay_address(self) -> str:
        """Decrypt and return the payment address."""
        from apps.crypto_bridge.symmetric import decrypt_field, get_field_encryption_key

        if not self.pay_address_encrypted:
            return ""
        fek = get_field_encryption_key()
        return decrypt_field(self.pay_address_encrypted, fek, str(self.id).encode())

    def set_pay_address(self, address: str) -> None:
        """Encrypt and store the payment address."""
        from apps.crypto_bridge.symmetric import encrypt_field, get_field_encryption_key

        fek = get_field_encryption_key()
        self.pay_address_encrypted = encrypt_field(address, fek, str(self.id).encode())


class FiatPayment(models.Model):
    """
    Fiat currency payment details for a Transaction.

    Handles Stripe (card) and Wise (bank transfer) payments.
    Bank account numbers are encrypted at rest.
    """

    class Method(models.TextChoices):
        STRIPE_CARD = "stripe_card", "Stripe Card"
        STRIPE_SEPA = "stripe_sepa", "Stripe SEPA"
        WISE_BANK = "wise_bank", "Wise Bank Transfer"
        WISE_SWIFT = "wise_swift", "Wise SWIFT"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.OneToOneField(
        Transaction, on_delete=models.CASCADE, related_name="fiat_payment"
    )

    method = models.CharField(max_length=20, choices=Method.choices)

    # Stripe
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True, db_index=True)
    stripe_charge_id = models.CharField(max_length=100, blank=True)

    # Wise
    wise_transfer_id = models.CharField(max_length=100, blank=True)
    wise_quote_id = models.CharField(max_length=100, blank=True)

    # Bank details (encrypted)
    bank_account_encrypted = models.TextField(blank=True)
    bank_routing_encrypted = models.TextField(blank=True)

    # Exchange rate at time of payment
    exchange_rate = models.DecimalField(max_digits=20, decimal_places=8, null=True, blank=True)
    fee_amount = models.DecimalField(max_digits=20, decimal_places=8, null=True, blank=True)
    fee_currency = models.CharField(max_length=10, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bp_fiat_payments"

    def get_bank_account(self) -> str:
        """Decrypt and return the bank account number."""
        from apps.crypto_bridge.symmetric import decrypt_field, get_field_encryption_key

        if not self.bank_account_encrypted:
            return ""
        fek = get_field_encryption_key()
        return decrypt_field(self.bank_account_encrypted, fek, str(self.id).encode())


class WebhookEvent(models.Model):
    """
    Inbound webhook events from payment providers (NOWPayments, Stripe, Wise).

    Raw payloads are stored for replay / debugging.  HMAC signatures are
    verified before the event is processed.
    """

    class Provider(models.TextChoices):
        NOWPAYMENTS = "nowpayments", "NOWPayments"
        STRIPE = "stripe", "Stripe"
        WISE = "wise", "Wise"
        TRANSAK = "transak", "Transak"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.CharField(max_length=20, choices=Provider.choices, db_index=True)
    event_type = models.CharField(max_length=80, db_index=True)
    provider_event_id = models.CharField(max_length=200, blank=True, db_index=True)

    payload = models.JSONField()
    raw_body = models.TextField(blank=True)

    signature_valid = models.BooleanField(default=False)
    processed = models.BooleanField(default=False)
    processed_at = models.DateTimeField(null=True, blank=True)

    related_transaction = models.ForeignKey(
        Transaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="webhook_events",
    )

    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "bp_webhook_events"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["provider", "processed"]),
            models.Index(fields=["provider_event_id"]),
        ]
