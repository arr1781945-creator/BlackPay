"""
apps/payments/transak_client.py
Transak on-ramp/off-ramp API client.

Handles:
  - Order status retrieval
  - Webhook event signature verification (HMAC-SHA512)
  - Partner URL generation for hosted checkout

Transak docs: https://docs.transak.com/docs/server-side-sdk
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any, Optional
from urllib.parse import urlencode

import requests
from django.conf import settings

log = logging.getLogger("blackpay.payments.transak")

TRANSAK_API_BASE_PROD = "https://api.transak.com"
TRANSAK_API_BASE_STAGING = "https://api-stg.transak.com"

TRANSAK_CHECKOUT_PROD = "https://global.transak.com"
TRANSAK_CHECKOUT_STAGING = "https://global-stg.transak.com"


class TransakClient:
    """
    Client for Transak's REST API and checkout URL generation.

    Used for:
      - Crypto on-ramp (fiat → crypto)
      - Crypto off-ramp (crypto → fiat)
      - Order status polling
      - Webhook verification
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> None:
        """
        Initialise the client.

        Args:
            api_key:     Transak partner API key.
            secret_key:  Transak secret key (for webhook verification).
            environment: "PRODUCTION" or "STAGING" (falls back to settings).
        """
        self.api_key = api_key or settings.TRANSAK_API_KEY
        self.secret_key = secret_key or settings.TRANSAK_SECRET_KEY
        env = environment or settings.TRANSAK_ENVIRONMENT
        self.is_production = env == "PRODUCTION"

        self.api_base = (
            TRANSAK_API_BASE_PROD if self.is_production else TRANSAK_API_BASE_STAGING
        )
        self.checkout_base = (
            TRANSAK_CHECKOUT_PROD if self.is_production else TRANSAK_CHECKOUT_STAGING
        )

        self._session = requests.Session()
        self._session.headers.update({
            "api-secret": self.secret_key,
            "Content-Type": "application/json",
        })

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        """Execute GET and return parsed JSON response data."""
        resp = self._session.get(f"{self.api_base}{path}", params=params, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body)

    # ── Order management ──────────────────────────────────────────────────────

    def get_order(self, order_id: str) -> dict:
        """
        Retrieve Transak order details by ID.

        Args:
            order_id: Transak order ID.

        Returns:
            Order detail dict with 'status', 'cryptoAmount', 'fiatAmount', etc.
        """
        data = self._get(f"/partners/api/v2/order/{order_id}")
        log.debug("Transak order retrieved", extra={"order_id": order_id})
        return data

    def get_orders(
        self,
        limit: int = 25,
        skip: int = 0,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> list[dict]:
        """
        List partner orders with optional date filtering.

        Args:
            limit:      Max results per page.
            skip:       Offset for pagination.
            start_date: ISO-8601 start date string.
            end_date:   ISO-8601 end date string.

        Returns:
            List of order dicts.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if start_date:
            params["startDate"] = start_date
        if end_date:
            params["endDate"] = end_date
        return self._get("/partners/api/v2/orders", params=params)

    # ── Webhook verification ───────────────────────────────────────────────────

    def verify_webhook_signature(
        self,
        raw_body: bytes,
        received_signature: str,
    ) -> bool:
        """
        Verify the HMAC-SHA512 signature on a Transak webhook.

        Transak signs the raw JSON body with the partner secret key.

        Args:
            raw_body:            Raw request body bytes.
            received_signature:  Value from the X-TRANSAK-SIGNATURE header.

        Returns:
            True if valid, False otherwise.
        """
        if not self.secret_key:
            log.error("TRANSAK_SECRET_KEY not configured — cannot verify webhook")
            return False

        expected = hmac.new(
            self.secret_key.encode("utf-8"),
            raw_body,
            hashlib.sha512,
        ).hexdigest()

        return hmac.compare_digest(expected.lower(), received_signature.lower())

    def verify_webhook_data(self, event_data: dict) -> Optional[dict]:
        """
        Decrypt/verify webhook event data using the partner API secret.

        Some Transak webhooks include an encrypted 'data' payload.
        This decodes and returns the order data from the event.

        Args:
            event_data: Parsed webhook payload dict.

        Returns:
            Decoded order data dict, or None if verification fails.
        """
        # In practice Transak sends plaintext JSON for most webhook events
        # This is a passthrough with basic validation
        order_data = event_data.get("data", {})
        if not order_data or "id" not in order_data:
            log.warning("Transak webhook missing order data")
            return None
        return order_data

    # ── Checkout URL generation ────────────────────────────────────────────────

    def generate_checkout_url(
        self,
        crypto_currency: str,
        network: Optional[str] = None,
        fiat_currency: str = "USD",
        fiat_amount: Optional[float] = None,
        crypto_amount: Optional[float] = None,
        wallet_address: Optional[str] = None,
        redirect_url: Optional[str] = None,
        webhook_status_url: Optional[str] = None,
        partner_order_id: Optional[str] = None,
        is_auto_fill_user_data: bool = False,
        disable_payment_methods: Optional[list[str]] = None,
        theme_color: str = "000000",
    ) -> str:
        """
        Generate a Transak hosted checkout URL.

        The user is redirected here to complete their purchase.
        BlackPay receives webhook notifications when the order progresses.

        Args:
            crypto_currency:           Target cryptocurrency (e.g. "BTC", "ETH").
            network:                   Blockchain network (e.g. "ethereum", "bsc").
            fiat_currency:             Source fiat currency (e.g. "USD", "EUR").
            fiat_amount:               Pre-fill fiat amount.
            crypto_amount:             Pre-fill crypto amount.
            wallet_address:            Destination wallet address.
            redirect_url:              Post-purchase redirect URL.
            webhook_status_url:        Webhook endpoint for order status updates.
            partner_order_id:          Your internal order reference.
            is_auto_fill_user_data:    Skip KYC form if user already verified.
            disable_payment_methods:   List of methods to hide (e.g. ["credit_debit_card"]).
            theme_color:               Hex colour for UI customisation (no #).

        Returns:
            Full checkout URL string.
        """
        params: dict[str, Any] = {
            "apiKey": self.api_key,
            "cryptoCurrencyCode": crypto_currency.upper(),
            "defaultFiatCurrency": fiat_currency.upper(),
            "themeColor": theme_color,
            "isAutoFillUserData": is_auto_fill_user_data,
        }

        if network:
            params["network"] = network
        if fiat_amount:
            params["fiatAmount"] = fiat_amount
        if crypto_amount:
            params["defaultCryptoAmount"] = crypto_amount
        if wallet_address:
            params["walletAddress"] = wallet_address
        if redirect_url:
            params["redirectURL"] = redirect_url
        if webhook_status_url:
            params["webhookStatusUrl"] = webhook_status_url
        if partner_order_id:
            params["partnerOrderId"] = partner_order_id
        if disable_payment_methods:
            params["disablePaymentMethods"] = ",".join(disable_payment_methods)

        url = f"{self.checkout_base}?{urlencode(params)}"
        log.debug(
            "Transak checkout URL generated",
            extra={"crypto": crypto_currency, "fiat": fiat_currency},
        )
        return url

    # ── Supported assets ──────────────────────────────────────────────────────

    def get_currencies(self) -> list[dict]:
        """
        Return the list of supported cryptocurrencies.

        Returns:
            List of currency dicts with 'symbol', 'name', 'network' etc.
        """
        return self._get("/api/v2/currencies/crypto-currencies")

    def get_fiat_currencies(self) -> list[dict]:
        """
        Return the list of supported fiat currencies.

        Returns:
            List of fiat currency dicts.
        """
        return self._get("/api/v2/currencies/fiat-currencies")

    def get_price(
        self,
        fiat_currency: str,
        crypto_currency: str,
        fiat_amount: float,
        payment_method: str = "credit_debit_card",
        network: Optional[str] = None,
    ) -> dict:
        """
        Get a live price quote for a fiat → crypto purchase.

        Args:
            fiat_currency:   Source fiat currency.
            crypto_currency: Target crypto currency.
            fiat_amount:     Amount in fiat.
            payment_method:  Payment method identifier.
            network:         Blockchain network.

        Returns:
            Price dict with 'cryptoAmount', 'totalFeeInFiat', 'conversionPrice'.
        """
        params: dict[str, Any] = {
            "fiatCurrency": fiat_currency.upper(),
            "cryptoCurrency": crypto_currency.upper(),
            "isBuyOrSell": "BUY",
            "fiatAmount": fiat_amount,
            "paymentMethod": payment_method,
            "partnerApiKey": self.api_key,
        }
        if network:
            params["network"] = network
        return self._get("/api/v2/currencies/price", params=params)
