"""
apps/api/exceptions.py
Custom DRF exception handler for uniform BlackPay error responses.

All errors follow:
  {
    "error": "<exception_class_name>",
    "detail": "<message or dict>",
    "status_code": <int>
  }
"""

from __future__ import annotations

import logging

from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler

log = logging.getLogger("blackpay.api.exceptions")


def blackpay_exception_handler(exc: Exception, context: dict) -> Response | None:
    """
    Custom exception handler that wraps DRF responses in a consistent envelope.

    Falls back to DRF's default handler for unrecognised exceptions,
    which then returns None (triggering Django's 500 handler).

    Args:
        exc:     The raised exception.
        context: DRF view context dict.

    Returns:
        Response with uniform error envelope, or None.
    """
    response = exception_handler(exc, context)

    if response is not None:
        error_class = type(exc).__name__
        detail = response.data

        # Flatten single-key 'detail' responses
        if isinstance(detail, dict) and list(detail.keys()) == ["detail"]:
            detail = detail["detail"]

        response.data = {
            "error": error_class,
            "detail": detail,
            "status_code": response.status_code,
        }

        if response.status_code >= 500:
            log.error(
                "Server error",
                extra={"error": error_class, "detail": str(detail)},
                exc_info=exc,
            )

    return response
