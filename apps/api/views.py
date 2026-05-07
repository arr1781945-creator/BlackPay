"""
apps/api/views.py
Meta API endpoints: health check, version, PQC algorithm registry.
"""

from __future__ import annotations

from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView


class HealthView(APIView):
    """
    GET /api/v1/health/
    Platform health check — verifies DB, Redis, IPFS, crypto engine.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request: Request) -> Response:
        """Return service health status."""
        checks: dict = {}

        # Database
        try:
            from django.db import connection
            with connection.cursor() as cur:
                cur.execute("SELECT 1")
            checks["database"] = "ok"
        except Exception as exc:
            checks["database"] = f"error: {exc}"

        # Redis
        try:
            from django.core.cache import cache
            cache.set("_health_check", "1", timeout=5)
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {exc}"

        # Crypto engine
        try:
            from apps.crypto_bridge.loader import get_engine
            eng = get_engine()
            checks["crypto_engine"] = f"ok (v{eng.VERSION})"
        except Exception as exc:
            checks["crypto_engine"] = f"error: {exc}"

        # IPFS
        try:
            from apps.ipfs_storage.ipfs_client import IPFSClient
            checks["ipfs"] = "ok" if IPFSClient().is_available() else "unavailable"
        except Exception as exc:
            checks["ipfs"] = f"error: {exc}"

        all_ok = all(v == "ok" or v.startswith("ok") for v in checks.values())
        from rest_framework import status

        return Response(
            {"status": "healthy" if all_ok else "degraded", "checks": checks},
            status=status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class VersionView(APIView):
    """
    GET /api/v1/version/
    Return platform and crypto engine version info.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request: Request) -> Response:
        """Return version information."""
        crypto_version = "unknown"
        try:
            from apps.crypto_bridge.loader import get_engine
            crypto_version = get_engine().VERSION
        except Exception:
            pass

        return Response({
            "platform": "BlackPay",
            "api_version": "v1",
            "crypto_engine_version": crypto_version,
            "pqc_default_kem": __import__("django.conf", fromlist=["settings"]).settings.PQC_DEFAULT_KEM,
            "pqc_default_sig": __import__("django.conf", fromlist=["settings"]).settings.PQC_DEFAULT_SIG,
        })


class PQCAlgorithmsView(APIView):
    """
    GET /api/v1/pqc/algorithms/
    List all supported PQC algorithms with metadata.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return full algorithm registry."""
        from blackpay.pqc_config import KEM_ALGORITHMS, SIG_ALGORITHMS
        from dataclasses import asdict

        return Response({
            "kem": {k: asdict(v) for k, v in KEM_ALGORITHMS.items()},
            "sig": {k: asdict(v) for k, v in SIG_ALGORITHMS.items()},
        })
