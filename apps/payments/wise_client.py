"""
apps/payments/wise_client.py
Wise (TransferWise) API client for international bank transfers.

Covers:
  - Quote creation (exchange rate + fee estimate)
  - Recipient account creation
  - Transfer creation and funding
  - Transfer status polling

API docs: https://docs.wise.com/api-docs/api-reference
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Optional

import requests
from django.conf import settings

log = logging.getLogger("blackpay.payments.wise")

WISE_API_BASE = "https://api.transferwise.com"
WISE_SANDBOX_BASE = "https://api.sandbox.transferwise.tech"


class WiseClient:
    """
    HTTP client for the Wise REST API.

    Authenticates with a Bearer token (API token from Wise dashboard).
    """

    def __init__(
        self,
        api_token: Optional[str] = None,
        profile_id: Optional[str] = None,
        sandbox: bool = False,
    ) -> None:
        """
        Initialise the client.

        Args:
            api_token:  Wise API token (falls back to settings.WISE_API_TOKEN).
            profile_id: Wise profile ID (falls back to settings.WISE_PROFILE_ID).
            sandbox:    Use sandbox API if True.
        """
        self.api_token = api_token or settings.WISE_API_TOKEN
        self.profile_id = profile_id or settings.WISE_PROFILE_ID
        self.base_url = WISE_SANDBOX_BASE if sandbox else WISE_API_BASE

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        })

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        """Execute GET and return parsed JSON."""
        resp = self._session.get(f"{self.base_url}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> Any:
        """Execute POST and return parsed JSON."""
        resp = self._session.post(f"{self.base_url}{path}", json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ── Profiles ──────────────────────────────────────────────────────────────

    def get_profiles(self) -> list[dict]:
        """
        Return all personal and business profiles for the API token.

        Returns:
            List of profile dicts with 'id', 'type', 'details'.
        """
        return self._get("/v1/profiles")

    # ── Quotes ────────────────────────────────────────────────────────────────

    def create_quote(
        self,
        source_currency: str,
        target_currency: str,
        source_amount: Optional[Decimal] = None,
        target_amount: Optional[Decimal] = None,
        target_account: Optional[str] = None,
    ) -> dict:
        """
        Create an exchange rate quote.

        Specify EITHER source_amount OR target_amount (not both).

        Args:
            source_currency: Currency sending from (e.g. "GBP").
            target_currency: Currency delivering to (e.g. "EUR").
            source_amount:   How much to send (source_currency).
            target_amount:   How much to deliver (target_currency).
            target_account:  Recipient account ID (optional, improves fee estimate).

        Returns:
            Quote dict with 'id', 'rate', 'fee', 'estimatedDelivery'.
        """
        payload: dict[str, Any] = {
            "sourceCurrency": source_currency.upper(),
            "targetCurrency": target_currency.upper(),
            "profile": self.profile_id,
            "payOut": "BANK_TRANSFER",
        }
        if source_amount is not None:
            payload["sourceAmount"] = float(source_amount)
        elif target_amount is not None:
            payload["targetAmount"] = float(target_amount)
        else:
            raise ValueError("Either source_amount or target_amount is required.")

        if target_account:
            payload["targetAccount"] = target_account

        quote = self._post("/v3/profiles/{}/quotes".format(self.profile_id), payload)
        log.info(
            "Wise quote created",
            extra={
                "quote_id": quote.get("id"),
                "source": source_currency,
                "target": target_currency,
            },
        )
        return quote

    def get_quote(self, quote_id: str) -> dict:
        """
        Retrieve an existing quote by ID.

        Args:
            quote_id: Wise quote UUID.

        Returns:
            Quote dict.
        """
        return self._get(f"/v3/profiles/{self.profile_id}/quotes/{quote_id}")

    # ── Recipient accounts ─────────────────────────────────────────────────────

    def create_recipient_account(
        self,
        currency: str,
        account_holder_name: str,
        account_details: dict,
        legal_type: str = "PRIVATE",
    ) -> dict:
        """
        Create a recipient bank account.

        Args:
            currency:             Account currency (e.g. "EUR").
            account_holder_name:  Full name of account holder.
            account_details:      Currency-specific details dict.
                                  e.g. {"IBAN": "DE89...", "BIC": "DEUTDEDB"}
            legal_type:           "PRIVATE" or "BUSINESS".

        Returns:
            Recipient account dict with 'id'.
        """
        payload: dict[str, Any] = {
            "currency": currency.upper(),
            "type": self._get_account_type(currency),
            "profile": self.profile_id,
            "ownedByCustomer": False,
            "accountHolderName": account_holder_name,
            "legalType": legal_type,
            "details": account_details,
        }
        account = self._post("/v1/accounts", payload)
        log.info(
            "Wise recipient created",
            extra={"account_id": account.get("id"), "currency": currency},
        )
        return account

    def get_recipient_accounts(self, currency: Optional[str] = None) -> list[dict]:
        """
        List recipient accounts for the profile.

        Args:
            currency: Filter by currency (optional).

        Returns:
            List of recipient account dicts.
        """
        params: dict[str, Any] = {"profile": self.profile_id}
        if currency:
            params["currency"] = currency.upper()
        return self._get("/v1/accounts", params=params)

    # ── Transfers ─────────────────────────────────────────────────────────────

    def create_transfer(
        self,
        target_account_id: str,
        quote_id: str,
        customer_transaction_id: str,
        reference: Optional[str] = None,
    ) -> dict:
        """
        Create a Wise transfer from a quote and recipient account.

        Args:
            target_account_id:        Recipient account ID (from create_recipient_account).
            quote_id:                 Quote ID (from create_quote).
            customer_transaction_id:  Your idempotency key (e.g. BlackPay transaction UUID).
            reference:                Payment reference shown on bank statement.

        Returns:
            Transfer dict with 'id' and 'status'.
        """
        payload: dict[str, Any] = {
            "targetAccount": target_account_id,
            "quoteUuid": quote_id,
            "customerTransactionId": customer_transaction_id,
        }
        if reference:
            payload["details"] = {"reference": reference}

        transfer = self._post("/v1/transfers", payload)
        log.info(
            "Wise transfer created",
            extra={"transfer_id": transfer.get("id"), "quote_id": quote_id},
        )
        return transfer

    def fund_transfer(self, transfer_id: str) -> dict:
        """
        Fund a transfer from the profile balance.

        The profile must have sufficient balance in the source currency.

        Args:
            transfer_id: Wise transfer ID.

        Returns:
            Funding result dict with 'status'.
        """
        result = self._post(
            f"/v3/profiles/{self.profile_id}/transfers/{transfer_id}/payments",
            {"type": "BALANCE"},
        )
        log.info(
            "Wise transfer funded",
            extra={"transfer_id": transfer_id, "status": result.get("status")},
        )
        return result

    def get_transfer(self, transfer_id: str) -> dict:
        """
        Retrieve transfer details and current status.

        Args:
            transfer_id: Wise transfer ID.

        Returns:
            Transfer dict with 'status':
            'incoming_payment_waiting' | 'processing' | 'funds_converted' |
            'outgoing_payment_sent' | 'cancelled' | 'funds_refunded'
        """
        return self._get(f"/v1/transfers/{transfer_id}")

    def cancel_transfer(self, transfer_id: str) -> dict:
        """
        Cancel a transfer that has not yet been funded.

        Args:
            transfer_id: Wise transfer ID.

        Returns:
            Updated transfer dict.
        """
        resp = self._session.put(
            f"{self.base_url}/v1/transfers/{transfer_id}/cancel",
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Balance ───────────────────────────────────────────────────────────────

    def get_balances(self, types: str = "STANDARD") -> list[dict]:
        """
        Return balance accounts for the profile.

        Args:
            types: Account type filter (STANDARD, SAVINGS).

        Returns:
            List of balance account dicts.
        """
        return self._get(
            f"/v4/profiles/{self.profile_id}/balances",
            params={"types": types},
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_account_type(currency: str) -> str:
        """
        Map a currency to its typical Wise account type identifier.

        Args:
            currency: ISO currency code.

        Returns:
            Wise account type string.
        """
        sepa_currencies = {"EUR", "DKK", "SEK", "NOK", "PLN", "HUF", "CZK", "RON"}
        if currency.upper() in sepa_currencies:
            return "iban"
        if currency.upper() == "GBP":
            return "sort_code"
        if currency.upper() in {"USD", "CAD"}:
            return "aba"
        return "swift_code"
