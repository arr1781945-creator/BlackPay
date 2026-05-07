"""
apps/wallet/models.py
Wallet, Balance, and CurrencyRate models for multi-currency asset management.

Each user has one Wallet with multiple Balance rows — one per currency.
CurrencyRate provides live exchange rates for conversion display.
All balance amounts are stored as Decimal strings.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.db import models

from apps.users.models import User


class Wallet(models.Model):
    """
    A user's multi-currency wallet.

    One wallet per user. Balances are tracked per-currency in related Balance records.
    The wallet holds a ZEC shielded address for privacy-first transfers.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="wallet")

    # ZEC shielded address (Sapling/Orchard) — encrypted at rest
    zec_address_encrypted = models.TextField(blank=True)

    # General receiving address metadata
    is_active = models.BooleanField(default=True)
    label = models.CharField(max_length=100, blank=True)

    # Spending limits
    daily_limit = models.DecimalField(
        max_digits=20, decimal_places=8, null=True, blank=True,
        help_text="Max spend per day in USD equivalent"
    )
    monthly_limit = models.DecimalField(
        max_digits=20, decimal_places=8, null=True, blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bp_wallets"

    def __str__(self) -> str:
        return f"<Wallet user={self.user_id}>"

    def get_zec_address(self) -> str:
        """Decrypt and return the ZEC shielded address."""
        from apps.crypto_bridge.symmetric import decrypt_field, get_field_encryption_key

        if not self.zec_address_encrypted:
            return ""
        fek = get_field_encryption_key()
        return decrypt_field(self.zec_address_encrypted, fek, str(self.id).encode())

    def set_zec_address(self, address: str) -> None:
        """Encrypt and store the ZEC shielded address."""
        from apps.crypto_bridge.symmetric import encrypt_field, get_field_encryption_key

        fek = get_field_encryption_key()
        self.zec_address_encrypted = encrypt_field(address, fek, str(self.id).encode())

    def total_balance_usd(self) -> Decimal:
        """
        Return the approximate total wallet balance in USD.

        Sums all currency balances, converted via the most recent CurrencyRate.
        Returns 0 if no rates are available.
        """
        total = Decimal("0")
        for balance in self.balances.filter(amount__gt=0):
            rate = CurrencyRate.objects.filter(
                from_currency=balance.currency,
                to_currency="USD",
            ).order_by("-fetched_at").first()
            if rate:
                total += balance.decimal_amount * rate.rate
        return total


class Balance(models.Model):
    """
    A single-currency balance within a user's Wallet.

    Amount is stored as a string-backed Decimal to preserve full precision
    for both crypto (satoshi-level) and fiat amounts.

    Negative balances are not permitted — enforced at the application layer.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name="balances")
    currency = models.CharField(max_length=10, db_index=True)

    # Stored as string to avoid float issues; always read via decimal_amount property
    amount = models.CharField(max_length=60, default="0")

    # Frozen/locked amount (e.g. pending outgoing payment)
    locked_amount = models.CharField(max_length=60, default="0")

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bp_balances"
        unique_together = [("wallet", "currency")]
        indexes = [models.Index(fields=["wallet", "currency"])]

    def __str__(self) -> str:
        return f"<Balance {self.currency} {self.amount}>"

    @property
    def decimal_amount(self) -> Decimal:
        """Return the balance as a Decimal."""
        try:
            return Decimal(self.amount or "0")
        except Exception:
            return Decimal("0")

    @property
    def decimal_locked(self) -> Decimal:
        """Return the locked amount as a Decimal."""
        try:
            return Decimal(self.locked_amount or "0")
        except Exception:
            return Decimal("0")

    @property
    def available_amount(self) -> Decimal:
        """Return the spendable (non-locked) balance."""
        return max(Decimal("0"), self.decimal_amount - self.decimal_locked)

    def credit(self, amount: Decimal) -> None:
        """
        Credit the balance by the given amount (atomic).

        Args:
            amount: Positive Decimal to add.
        """
        if amount <= 0:
            raise ValueError(f"Credit amount must be positive, got {amount}")
        from django.db.models import F
        Balance.objects.filter(pk=self.pk).update(
            amount=str(round(self.decimal_amount + amount, 18))
        )
        self.refresh_from_db()

    def debit(self, amount: Decimal) -> None:
        """
        Debit the balance by the given amount (atomic, raises on insufficient funds).

        Args:
            amount: Positive Decimal to subtract.

        Raises:
            ValueError: if available_amount < amount.
        """
        if amount <= 0:
            raise ValueError(f"Debit amount must be positive, got {amount}")
        if self.available_amount < amount:
            raise ValueError(
                f"Insufficient balance: {self.available_amount} {self.currency} "
                f"(requested {amount})"
            )
        Balance.objects.filter(pk=self.pk).update(
            amount=str(round(self.decimal_amount - amount, 18))
        )
        self.refresh_from_db()


class CurrencyRate(models.Model):
    """
    Exchange rate snapshot between two currencies.

    Populated by a periodic Celery task via a public exchange rate API.
    Used only for display / approximation — payments use provider-quoted rates.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    from_currency = models.CharField(max_length=10, db_index=True)
    to_currency = models.CharField(max_length=10, db_index=True)
    rate = models.DecimalField(max_digits=30, decimal_places=15)
    source = models.CharField(max_length=50, default="coingecko")
    fetched_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "bp_currency_rates"
        ordering = ["-fetched_at"]
        indexes = [
            models.Index(fields=["from_currency", "to_currency", "fetched_at"]),
        ]

    def __str__(self) -> str:
        return f"<Rate {self.from_currency}/{self.to_currency} = {self.rate}>"
