"""
apps/payments/stripe_client.py
Stripe payment client for card and SEPA Direct Debit payments.

Handles:
  - PaymentIntent creation and confirmation
  - Webhook signature verification
  - Refunds
  - Customer management
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Optional

import stripe
from django.conf import settings

log = logging.getLogger("blackpay.payments.stripe")


def _get_stripe() -> stripe:
    """Configure and return the stripe module."""
    stripe.api_key = settings.STRIPE_SECRET_KEY
    stripe.api_version = "2024-06-20"
    return stripe


class StripeClient:
    """
    Wrapper around the Stripe Python SDK.

    All amounts passed to Stripe are converted to the smallest currency unit
    (cents for USD, pence for GBP, etc.) using _to_stripe_amount().
    """

    ZERO_DECIMAL_CURRENCIES = {
        "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW",
        "MGA", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
    }

    def __init__(self) -> None:
        self._stripe = _get_stripe()

    @staticmethod
    def _to_stripe_amount(amount: Decimal, currency: str) -> int:
        """
        Convert Decimal amount to Stripe's integer smallest-unit format.

        Args:
            amount:   Decimal amount (e.g. 10.50 for USD).
            currency: ISO 4217 currency code.

        Returns:
            Integer in smallest unit (e.g. 1050 cents for $10.50 USD).
        """
        if currency.upper() in StripeClient.ZERO_DECIMAL_CURRENCIES:
            return int(amount)
        return int(amount * 100)

    # ── Customers ─────────────────────────────────────────────────────────────

    def create_customer(self, email: str, user_id: str) -> dict:
        """
        Create a Stripe Customer object.

        Args:
            email:   Customer email address.
            user_id: BlackPay user UUID stored as Stripe metadata.

        Returns:
            Stripe Customer dict.
        """
        customer = self._stripe.Customer.create(
            email=email,
            metadata={"blackpay_user_id": user_id},
        )
        log.info("Stripe customer created", extra={"customer_id": customer["id"]})
        return dict(customer)

    def get_customer(self, customer_id: str) -> dict:
        """Retrieve a Stripe Customer by ID."""
        return dict(self._stripe.Customer.retrieve(customer_id))

    # ── PaymentIntents ────────────────────────────────────────────────────────

    def create_payment_intent(
        self,
        amount: Decimal,
        currency: str,
        payment_method_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        order_id: Optional[str] = None,
        description: Optional[str] = None,
        confirm: bool = False,
        return_url: Optional[str] = None,
    ) -> dict:
        """
        Create a Stripe PaymentIntent.

        Args:
            amount:            Payment amount as Decimal.
            currency:          ISO 4217 currency code.
            payment_method_id: Stripe PaymentMethod ID to attach.
            customer_id:       Stripe Customer ID.
            order_id:          BlackPay transaction UUID stored as metadata.
            description:       Human-readable description.
            confirm:           Attempt immediate confirmation if True.
            return_url:        Required when confirm=True for 3DS flows.

        Returns:
            Stripe PaymentIntent dict including 'client_secret'.
        """
        params: dict = {
            "amount": self._to_stripe_amount(amount, currency),
            "currency": currency.lower(),
            "automatic_payment_methods": {"enabled": True},
            "metadata": {"blackpay_order_id": order_id or ""},
        }
        if payment_method_id:
            params["payment_method"] = payment_method_id
        if customer_id:
            params["customer"] = customer_id
        if description:
            params["description"] = description
        if confirm:
            params["confirm"] = True
            params["return_url"] = return_url or ""

        pi = self._stripe.PaymentIntent.create(**params)
        log.info(
            "Stripe PaymentIntent created",
            extra={"pi_id": pi["id"], "amount": str(amount), "currency": currency},
        )
        return dict(pi)

    def retrieve_payment_intent(self, pi_id: str) -> dict:
        """Retrieve a PaymentIntent by ID."""
        return dict(self._stripe.PaymentIntent.retrieve(pi_id))

    def confirm_payment_intent(self, pi_id: str, payment_method_id: str) -> dict:
        """Confirm a PaymentIntent with a PaymentMethod."""
        return dict(self._stripe.PaymentIntent.confirm(pi_id, payment_method=payment_method_id))

    def cancel_payment_intent(self, pi_id: str) -> dict:
        """Cancel an uncaptured PaymentIntent."""
        pi = self._stripe.PaymentIntent.cancel(pi_id)
        log.info("Stripe PaymentIntent cancelled", extra={"pi_id": pi_id})
        return dict(pi)

    # ── Refunds ───────────────────────────────────────────────────────────────

    def create_refund(
        self,
        payment_intent_id: str,
        amount: Optional[Decimal] = None,
        reason: str = "requested_by_customer",
    ) -> dict:
        """
        Refund a completed PaymentIntent, fully or partially.

        Args:
            payment_intent_id: PaymentIntent ID to refund.
            amount:            Refund amount as Decimal (None = full refund).
            reason:            Stripe refund reason code.

        Returns:
            Stripe Refund dict.
        """
        params: dict = {"payment_intent": payment_intent_id, "reason": reason}
        if amount is not None:
            pi = self._stripe.PaymentIntent.retrieve(payment_intent_id)
            params["amount"] = self._to_stripe_amount(amount, pi["currency"])

        refund = self._stripe.Refund.create(**params)
        log.info("Stripe refund created", extra={"refund_id": refund["id"]})
        return dict(refund)

    # ── SEPA ──────────────────────────────────────────────────────────────────

    def create_sepa_payment_intent(
        self,
        amount: Decimal,
        currency: str = "eur",
        customer_id: Optional[str] = None,
        order_id: Optional[str] = None,
    ) -> dict:
        """
        Create a SEPA Direct Debit PaymentIntent.

        Args:
            amount:      EUR amount as Decimal.
            currency:    Must be 'eur' for SEPA.
            customer_id: Stripe Customer ID with SEPA payment method attached.
            order_id:    BlackPay transaction UUID.

        Returns:
            PaymentIntent dict.
        """
        params: dict = {
            "amount": self._to_stripe_amount(amount, currency),
            "currency": "eur",
            "payment_method_types": ["sepa_debit"],
            "metadata": {"blackpay_order_id": order_id or ""},
        }
        if customer_id:
            params["customer"] = customer_id
        pi = self._stripe.PaymentIntent.create(**params)
        log.info("Stripe SEPA PaymentIntent created", extra={"pi_id": pi["id"]})
        return dict(pi)

    # ── Webhook ───────────────────────────────────────────────────────────────

    def verify_webhook_signature(
        self,
        payload: bytes,
        sig_header: str,
        webhook_secret: Optional[str] = None,
    ) -> dict:
        """
        Verify a Stripe webhook signature and return the parsed event.

        Args:
            payload:        Raw request body bytes — do NOT decode before passing.
            sig_header:     Value of the Stripe-Signature HTTP header.
            webhook_secret: Stripe webhook signing secret (whsec_...).
                            Falls back to settings.STRIPE_WEBHOOK_SECRET.

        Returns:
            Parsed Stripe Event dict.

        Raises:
            stripe.error.SignatureVerificationError: on invalid signature.
            ValueError: if webhook secret is not configured.
        """
        secret = webhook_secret or settings.STRIPE_WEBHOOK_SECRET
        if not secret:
            raise ValueError("STRIPE_WEBHOOK_SECRET is not configured.")
        event = self._stripe.Webhook.construct_event(
            payload=payload, sig_header=sig_header, secret=secret,
        )
        return dict(event)
