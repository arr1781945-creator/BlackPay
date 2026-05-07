"""
apps/zk_layer/views.py
API views for ZK proof generation and verification.
"""

from __future__ import annotations

import logging
from decimal import Decimal

from rest_framework import permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.crypto_bridge.exceptions import CryptoError
from apps.zk_layer.zk_proof import (
    generate_balance_proof,
    generate_identity_proof,
    verify_balance_proof,
    verify_identity_proof,
)

log = logging.getLogger("blackpay.zk_layer.views")


class GenerateBalanceProofView(APIView):
    """
    POST /api/v1/zk/balance-proof/
    Generate a ZK sufficient-balance proof for the given amount/currency.

    Request body:
        { "amount": "100.00", "currency": "USD" }

    Response:
        { "proof": "<base64>" }
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Generate and return a ZK balance proof."""
        amount_str = request.data.get("amount")
        currency = request.data.get("currency", "").upper()

        if not amount_str or not currency:
            return Response(
                {"detail": "amount and currency are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            amount = Decimal(str(amount_str))
        except Exception:
            return Response({"detail": "Invalid amount."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            proof_b64 = generate_balance_proof(request.user, amount, currency)
        except CryptoError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"proof": proof_b64})


class VerifyBalanceProofView(APIView):
    """
    POST /api/v1/zk/balance-proof/verify/
    Verify a ZK balance proof.

    Request body:
        { "proof": "<base64>" }

    Response:
        { "valid": true }
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Verify a ZK balance proof."""
        proof_b64 = request.data.get("proof", "")
        if not proof_b64:
            return Response({"detail": "proof is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            valid = verify_balance_proof(proof_b64)
        except CryptoError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"valid": valid})


class GenerateIdentityProofView(APIView):
    """
    POST /api/v1/zk/identity-proof/
    Generate a Schnorr identity proof for a given challenge message.

    Request body:
        { "message_hex": "<hex>" }

    Response:
        { "proof": "<base64>", "public_key_hex": "..." }
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Generate a ZK identity proof."""
        message_hex = request.data.get("message_hex", "")
        if not message_hex:
            return Response(
                {"detail": "message_hex is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            message = bytes.fromhex(message_hex)
        except ValueError:
            return Response({"detail": "Invalid message_hex."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            proof_b64 = generate_identity_proof(request.user, message)
        except CryptoError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        # Return public key so verifier can check without a separate lookup
        from apps.users.models import PQCKey
        pk_hex = ""
        try:
            pqc_key = PQCKey.objects.get(
                user=request.user, key_type="sig", purpose="mfa", is_active=True
            )
            pk_hex = pqc_key.public_key_hex
        except Exception:
            pass

        return Response({"proof": proof_b64, "public_key_hex": pk_hex})


class VerifyIdentityProofView(APIView):
    """
    POST /api/v1/zk/identity-proof/verify/
    Verify a Schnorr identity proof.

    Request body:
        {
          "proof": "<base64>",
          "public_key_hex": "<hex>",
          "message_hex": "<hex>"
        }

    Response:
        { "valid": true }
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Verify a ZK identity proof."""
        proof_b64 = request.data.get("proof", "")
        public_key_hex = request.data.get("public_key_hex", "")
        message_hex = request.data.get("message_hex", "")

        if not all([proof_b64, public_key_hex, message_hex]):
            return Response(
                {"detail": "proof, public_key_hex, and message_hex are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            message = bytes.fromhex(message_hex)
        except ValueError:
            return Response({"detail": "Invalid message_hex."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            valid = verify_identity_proof(proof_b64, public_key_hex, message)
        except CryptoError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"valid": valid})
