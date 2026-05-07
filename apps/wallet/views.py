"""
apps/wallet/views.py
Wallet management API: balance retrieval, internal transfers, exchange rates.
"""

from __future__ import annotations

import logging
from decimal import Decimal

from django.db import transaction as db_transaction
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.users.models import User
from apps.users.pqc_auth import create_audit_log
from apps.wallet.models import Balance, CurrencyRate, Wallet
from apps.wallet.serializers import (
    CurrencyRateSerializer,
    TransferSerializer,
    WalletSerializer,
    WalletUpdateSerializer,
)

log = logging.getLogger("blackpay.wallet.views")


class WalletView(generics.RetrieveUpdateAPIView):
    """
    GET  /api/v1/wallet/
    PATCH /api/v1/wallet/
    Retrieve or update the current user's wallet (label, limits).
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method in ("PUT", "PATCH"):
            return WalletUpdateSerializer
        return WalletSerializer

    def get_object(self) -> Wallet:
        """Return or create the user's wallet."""
        wallet, _ = Wallet.objects.get_or_create(user=self.request.user)
        return wallet


class BalanceListView(generics.ListAPIView):
    """
    GET /api/v1/wallet/balances/
    List all currency balances for the current user's wallet.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        from apps.wallet.serializers import BalanceSerializer

        wallet, _ = Wallet.objects.get_or_create(user=self.request.user)
        return Balance.objects.filter(wallet=wallet)

    def get_serializer_class(self):
        from apps.wallet.serializers import BalanceSerializer

        return BalanceSerializer


class InternalTransferView(APIView):
    """
    POST /api/v1/wallet/transfer/
    Transfer funds between two BlackPay wallets.

    Both debit and credit are executed atomically.  A ZK balance proof
    can optionally be generated and stored on the transaction record.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Execute an internal wallet-to-wallet transfer."""
        serializer = TransferSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        sender = request.user
        recipient = User.objects.get(email=d["recipient_email"])
        amount = Decimal(str(d["amount"]))
        currency = d["currency"]

        if sender.id == recipient.id:
            return Response(
                {"detail": "Cannot transfer to yourself."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Optional ZK balance proof
        zk_proof_b64 = ""
        if d.get("include_zk_proof"):
            try:
                from apps.zk_layer.zk_proof import generate_balance_proof

                zk_proof_b64 = generate_balance_proof(sender, amount, currency)
            except Exception as exc:
                log.warning("ZK proof failed for transfer (non-fatal)", exc_info=exc)

        try:
            with db_transaction.atomic():
                # Sender balance
                sender_wallet, _ = Wallet.objects.get_or_create(user=sender)
                sender_balance, _ = Balance.objects.select_for_update().get_or_create(
                    wallet=sender_wallet,
                    currency=currency,
                    defaults={"amount": "0"},
                )
                sender_balance.debit(amount)  # raises ValueError on insufficient funds

                # Recipient balance
                recipient_wallet, _ = Wallet.objects.get_or_create(user=recipient)
                recipient_balance, _ = Balance.objects.select_for_update().get_or_create(
                    wallet=recipient_wallet,
                    currency=currency,
                    defaults={"amount": "0"},
                )
                recipient_balance.credit(amount)

                # Record as Transaction
                from apps.payments.models import Transaction

                tx = Transaction.objects.create(
                    user=sender,
                    payment_type="fiat",
                    status="completed",
                    amount=amount,
                    currency=currency,
                    provider="internal",
                    description=d.get("description", "Internal transfer"),
                    zk_balance_proof=zk_proof_b64,
                    completed_at=__import__("django.utils.timezone", fromlist=["timezone"]).timezone.now(),
                )
                tx.set_recipient_address(recipient.email)
                tx.save(update_fields=["recipient_address_encrypted"])

        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        create_audit_log(
            "transaction_completed",
            sender,
            {
                "type": "internal_transfer",
                "amount": str(amount),
                "currency": currency,
                "recipient_id": str(recipient.id),
            },
            request,
        )

        log.info(
            "Internal transfer completed",
            extra={
                "sender": str(sender.id),
                "recipient": str(recipient.id),
                "amount": str(amount),
                "currency": currency,
            },
        )

        return Response(
            {
                "detail": "Transfer successful.",
                "amount": str(amount),
                "currency": currency,
                "recipient": recipient.email,
                "new_balance": str(sender_balance.decimal_amount),
                "zk_proof_included": bool(zk_proof_b64),
            },
            status=status.HTTP_200_OK,
        )


class ExchangeRateListView(generics.ListAPIView):
    """
    GET /api/v1/wallet/rates/?from=BTC&to=USD
    List the latest exchange rates, optionally filtered by currency pair.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CurrencyRateSerializer

    def get_queryset(self):
        qs = CurrencyRate.objects.order_by("from_currency", "to_currency", "-fetched_at")

        from_currency = self.request.query_params.get("from")
        to_currency = self.request.query_params.get("to")

        if from_currency:
            qs = qs.filter(from_currency=from_currency.upper())
        if to_currency:
            qs = qs.filter(to_currency=to_currency.upper())

        # Return only the latest rate per pair (use distinct on currency pair)
        seen: set = set()
        results = []
        for rate in qs:
            key = (rate.from_currency, rate.to_currency)
            if key not in seen:
                seen.add(key)
                results.append(rate)
        return results
