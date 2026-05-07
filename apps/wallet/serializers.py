"""
apps/wallet/serializers.py
DRF serializers for Wallet, Balance, and CurrencyRate.
"""

from __future__ import annotations

from decimal import Decimal

from rest_framework import serializers

from apps.wallet.models import Balance, CurrencyRate, Wallet


class BalanceSerializer(serializers.ModelSerializer):
    """Single-currency balance."""

    available_amount = serializers.DecimalField(
        max_digits=36, decimal_places=18, read_only=True
    )
    decimal_amount = serializers.DecimalField(
        max_digits=36, decimal_places=18, read_only=True
    )
    decimal_locked = serializers.DecimalField(
        max_digits=36, decimal_places=18, read_only=True
    )

    class Meta:
        model = Balance
        fields = [
            "id", "currency", "decimal_amount",
            "decimal_locked", "available_amount", "updated_at",
        ]
        read_only_fields = fields


class WalletSerializer(serializers.ModelSerializer):
    """Full wallet with all currency balances."""

    balances = BalanceSerializer(many=True, read_only=True)
    total_balance_usd = serializers.DecimalField(
        max_digits=20, decimal_places=8, read_only=True
    )

    class Meta:
        model = Wallet
        fields = [
            "id", "is_active", "label", "daily_limit",
            "monthly_limit", "balances", "total_balance_usd",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "balances", "total_balance_usd", "created_at"]


class WalletUpdateSerializer(serializers.ModelSerializer):
    """Allow updating label and spending limits."""

    class Meta:
        model = Wallet
        fields = ["label", "daily_limit", "monthly_limit"]

    def validate_daily_limit(self, value: Decimal) -> Decimal:
        if value is not None and value < 0:
            raise serializers.ValidationError("Daily limit cannot be negative.")
        return value


class CurrencyRateSerializer(serializers.ModelSerializer):
    """Exchange rate snapshot."""

    class Meta:
        model = CurrencyRate
        fields = ["from_currency", "to_currency", "rate", "source", "fetched_at"]
        read_only_fields = fields


class TransferSerializer(serializers.Serializer):
    """
    Internal wallet-to-wallet transfer request.

    The recipient is identified by email.  Amount and currency are required.
    An optional ZK balance proof is generated if include_zk_proof=True.
    """

    recipient_email = serializers.EmailField()
    amount = serializers.DecimalField(
        max_digits=36, decimal_places=18, min_value=Decimal("0.000001")
    )
    currency = serializers.CharField(max_length=10)
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)
    include_zk_proof = serializers.BooleanField(default=False)

    def validate_currency(self, value: str) -> str:
        return value.upper()

    def validate_recipient_email(self, value: str) -> str:
        from apps.users.models import User

        if not User.objects.filter(email=value.lower(), is_active=True).exists():
            raise serializers.ValidationError("Recipient not found.")
        return value.lower()
