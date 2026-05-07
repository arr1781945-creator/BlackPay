"""
apps/payments/nowpayments.py
NOWPayments API client.

Handles:
  - Creating crypto payment invoices
  - Fetching payment status
  - IPN (Instant Payment Notification) signature verification

API docs: https://documenter.getpostman.com/view/7907941/2s93JqTRWN
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from decimal import Decimal
from typing import Any, Optional

import requests
from django.conf import settings

log = logging.getLogger("blackpay.payments.nowpayments")

NOWPAYMENTS_API_BASE = "https://api.nowpayments.io/v1"
NOWPAYMENTS_SANDBOX_BASE = "https://api-sandbox.nowpayments.io/v1"


class NOWPaymentsClient:
    """
    Thin wrapper around the NOWPayments REST API.

    All requests include the API key header.  Responses are parsed to dicts.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        ipn_secret: Optional[str] = None,
        sandbox: bool = False,
    ) -> None:
        """
        Initialise the client.

        Args:
            api_key:    NOWPayments API key (falls back to settings.NOWPAYMENTS_API_KEY).
            ipn_secret: IPN HMAC secret (falls back to settings.NOWPAYMENTS_IPN_SECRET).
            sandbox:    Use the sandbox API endpoint if True.
        """
        self.api_key = api_key or settings.NOWPAYMENTS_API_KEY
        self.ipn_secret = ipn_secret or settings.NOWPAYMENTS_IPN_SECRET
        self.base_url = NOWPAYMENTS_SANDBOX_BASE if sandbox else NOWPAYMENTS_API_BASE
        self._session = requests.Session()
        self._session.headers.update({
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
        })

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """Execute a GET request and return parsed JSON."""
        resp = self._session.get(f"{self.base_url}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> dict:
        """Execute a POST request and return parsed JSON."""
        resp = self._session.post(f"{self.base_url}{path}", json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """
        Check the NOWPayments API health status.

        Returns:
            Dict with 'message' key.
        """
        return self._get("/status")

    # ── Currencies ────────────────────────────────────────────────────────────

    def get_available_currencies(self) -> list[str]:
        """
        Return a list of all supported payment currencies.

        Returns:
            List of currency ticker strings, e.g. ['BTC', 'ETH', 'USDTTRC20', ...].
        """
        data = self._get("/currencies")
        return data.get("currencies", [])

    def get_estimate(
        self,
        amount: Decimal,
        currency_from: str,
        currency_to: str,
    ) -> dict:
        """
        Get estimated payment amount in pay_currency.

        Args:
            amount:        Amount in `currency_from`.
            currency_from: Source currency (e.g. USD).
            currency_to:   Pay currency (e.g. BTC).

        Returns:
            Dict with 'estimated_amount' and 'currency_from'/'currency_to'.
        """
        return self._get("/estimate", params={
            "amount": str(amount),
            "currency_from": currency_from.lower(),
            "currency_to": currency_to.lower(),
        })

    # ── Payments ──────────────────────────────────────────────────────────────

    def create_payment(
        self,
        price_amount: Decimal,
        price_currency: str,
        pay_currency: str,
        order_id: Optional[str] = None,
        order_description: Optional[str] = None,
        ipn_callback_url: Optional[str] = None,
        success_url: Optional[str] = None,
        cancel_url: Optional[str] = None,
    ) -> dict:
        """
        Create a new payment invoice.

        Args:
            price_amount:      Amount the customer should pay (in price_currency).
            price_currency:    Invoice currency (e.g. USD).
            pay_currency:      Cryptocurrency to pay with (e.g. BTC).
            order_id:          Your internal order reference.
            order_description: Human-readable description.
            ipn_callback_url:  URL for Instant Payment Notifications.
            success_url:       Redirect after payment.
            cancel_url:        Redirect on cancellation.

        Returns:
            NOWPayments payment object dict:
            {
              "payment_id": "...",
              "payment_status": "waiting",
              "pay_address": "...",
              "pay_amount": 0.00123,
              "pay_currency": "btc",
              ...
            }
        """
        payload: dict[str, Any] = {
            "price_amount": str(price_amount),
            "price_currency": price_currency.lower(),
            "pay_currency": pay_currency.lower(),
        }
        if order_id:
            payload["order_id"] = order_id
        if order_description:
            payload["order_description"] = order_description
        if ipn_callback_url:
            payload["ipn_callback_url"] = ipn_callback_url
        if success_url:
            payload["success_url"] = success_url
        if cancel_url:
            payload["cancel_url"] = cancel_url

        log.info(
            "Creating NOWPayments payment",
            extra={"amount": str(price_amount), "currency": price_currency, "pay": pay_currency},
        )
        return self._post("/payment", payload)

    def get_payment_status(self, payment_id: str) -> dict:
        """
        Retrieve the current status of a payment.

        Args:
            payment_id: NOWPayments payment ID.

        Returns:
            Payment status dict with 'payment_status' field.
        """
        return self._get(f"/payment/{payment_id}")

    def get_payments_list(
        self,
        limit: int = 100,
        page: int = 0,
        sort_by: str = "created_at",
        order_by: str = "asc",
    ) -> dict:
        """
        List payments with pagination.

        Returns:
            Dict with 'data' (list of payments) and 'total' count.
        """
        return self._get("/payment/", params={
            "limit": limit,
            "page": page,
            "sortBy": sort_by,
            "orderBy": order_by,
        })

    # ── IPN signature verification ────────────────────────────────────────────

    def verify_ipn_signature(
        self,
        payload: dict,
        received_hmac: str,
    ) -> bool:
        """
        Verify the HMAC-SHA512 signature on an IPN callback.

        NOWPayments signs the sorted JSON payload with the IPN secret.
        This must be checked before processing any IPN event.

        Args:
            payload:       Parsed JSON payload from the IPN request body.
            received_hmac: Value of the x-nowpayments-sig header.

        Returns:
            True if signature is valid, False otherwise.
        """
        if not self.ipn_secret:
            log.error("NOWPAYMENTS_IPN_SECRET not configured — cannot verify IPN")
            return False

        # Sort payload keys and serialise deterministically
        sorted_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        expected = hmac.new(
            self.ipn_secret.encode("utf-8"),
            sorted_payload.encode("utf-8"),
            hashlib.sha512,
        ).hexdigest()

        # Constant-time comparison
        return hmac.compare_digest(expected, received_hmac.lower())

    # ── Minimum amounts ───────────────────────────────────────────────────────

    def get_minimum_amount(self, currency_from: str, currency_to: str) -> dict:
        """
        Return the minimum payment amount for a currency pair.

        Args:
            currency_from: Price currency (e.g. USD).
            currency_to:   Pay currency (e.g. BTC).

        Returns:
            Dict with 'min_amount' field.
        """
        return self._get("/min-amount", params={
            "currency_from": currency_from.lower(),
            "currency_to": currency_to.lower(),
        })
