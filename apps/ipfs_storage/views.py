"""
apps/ipfs_storage/views.py
IPFS document upload and retrieval API.
"""

from __future__ import annotations

import logging

from rest_framework import permissions, status
from rest_framework.parsers import MultiPartParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.ipfs_storage.ipfs_client import IPFSClient

log = logging.getLogger("blackpay.ipfs.views")


class IPFSUploadView(APIView):
    """
    POST /api/v1/ipfs/upload/
    Upload an encrypted document to IPFS.

    Accepts multipart/form-data with:
      - file:          The document file.
      - document_type: Label (id_document, proof_of_address, selfie).

    Returns:
      { "cid": "<ipfs_cid>" }
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser]

    def post(self, request: Request) -> Response:
        """Encrypt and upload a document to IPFS."""
        file_obj = request.FILES.get("file")
        document_type = request.data.get("document_type", "document")

        if not file_obj:
            return Response({"detail": "file is required."}, status=status.HTTP_400_BAD_REQUEST)

        allowed_types = {"id_document", "proof_of_address", "selfie", "document"}
        if document_type not in allowed_types:
            return Response(
                {"detail": f"document_type must be one of {allowed_types}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        file_bytes = file_obj.read()
        if len(file_bytes) > 10 * 1024 * 1024:  # 10 MB limit
            return Response(
                {"detail": "File exceeds maximum size of 10MB."},
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        try:
            ipfs = IPFSClient()
            cid = ipfs.add_document(
                document_bytes=file_bytes,
                document_type=document_type,
                user_id=str(request.user.id),
            )
        except RuntimeError as exc:
            log.error("IPFS upload failed", exc_info=exc)
            return Response(
                {"detail": "IPFS service unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response({"cid": cid}, status=status.HTTP_201_CREATED)


class IPFSHealthView(APIView):
    """
    GET /api/v1/ipfs/health/
    Check IPFS daemon connectivity.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return IPFS daemon status."""
        ipfs = IPFSClient()
        available = ipfs.is_available()
        return Response(
            {"ipfs_available": available},
            status=status.HTTP_200_OK if available else status.HTTP_503_SERVICE_UNAVAILABLE,
        )
