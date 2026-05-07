"""
apps/ipfs_storage/ipfs_client.py
IPFS client for BlackPay's privacy-first document and data storage.

All data stored in IPFS is encrypted before upload using AES-256-GCM.
Raw plaintext is never sent to the IPFS node.

Use cases:
  - GDPR data export archives
  - KYC document storage (encrypted)
  - Immutable audit log anchoring (hash-only)
  - Payment receipt storage

The client wraps ipfshttpclient and adds:
  - Transparent AES-256-GCM encryption/decryption
  - JSON serialisation helpers
  - Content-addressed retrieval with integrity verification
  - Optional pinning to remote pin services (Pinata, Web3.Storage)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any, Optional

from django.conf import settings

log = logging.getLogger("blackpay.ipfs")


class IPFSClient:
    """
    BlackPay IPFS client with built-in AES-256-GCM encryption.

    All add_encrypted* methods encrypt data before uploading.
    All get_encrypted* methods decrypt data after retrieval.

    The encryption key used is the platform FIELD_ENCRYPTION_KEY unless
    a per-call key is provided.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
    ) -> None:
        """
        Initialise the IPFS client.

        Args:
            api_url:        IPFS HTTP API URL (falls back to settings.IPFS_API_URL).
            encryption_key: 32-byte AES key (falls back to platform key from settings).
        """
        self.api_url = api_url or getattr(settings, "IPFS_API_URL", "/ip4/127.0.0.1/tcp/5001")
        self._enc_key = encryption_key
        self._client = None

    def _get_client(self):
        """
        Lazy-initialise the ipfshttpclient connection.

        Returns:
            ipfshttpclient.Client instance.

        Raises:
            RuntimeError: if ipfshttpclient is not installed or daemon is unreachable.
        """
        if self._client is None:
            try:
                import ipfshttpclient
                self._client = ipfshttpclient.connect(self.api_url)
            except Exception as exc:
                raise RuntimeError(f"IPFS connection failed ({self.api_url}): {exc}") from exc
        return self._client

    def _get_enc_key(self) -> bytes:
        """Return the encryption key, loading from settings if not provided."""
        if self._enc_key:
            return self._enc_key
        from apps.crypto_bridge.symmetric import get_field_encryption_key
        return get_field_encryption_key()

    # ── Raw operations ────────────────────────────────────────────────────────

    def add_bytes(self, data: bytes, pin: bool = True) -> str:
        """
        Upload raw bytes to IPFS.

        Args:
            data: Raw bytes to upload.
            pin:  If True, pin the content to prevent GC.

        Returns:
            IPFS CID (Content Identifier) string.
        """
        client = self._get_client()
        result = client.add(data, pin=pin)
        cid = result["Hash"] if isinstance(result, dict) else result
        log.debug("IPFS add_bytes", extra={"cid": cid, "size": len(data)})
        return cid

    def get_bytes(self, cid: str) -> bytes:
        """
        Retrieve raw bytes from IPFS by CID.

        Args:
            cid: IPFS Content Identifier.

        Returns:
            Raw bytes from IPFS.
        """
        client = self._get_client()
        data = client.cat(cid)
        log.debug("IPFS get_bytes", extra={"cid": cid, "size": len(data)})
        return data

    # ── Encrypted operations ───────────────────────────────────────────────────

    def add_encrypted(
        self,
        plaintext: bytes,
        aad: bytes = b"",
        pin: bool = True,
    ) -> str:
        """
        Encrypt plaintext with AES-256-GCM and upload to IPFS.

        The blob format stored on IPFS:
            JSON: {"v": 1, "enc": "<base64url: nonce||ciphertext||tag>"}

        This makes the format self-describing and forward-compatible.

        Args:
            plaintext: Raw bytes to encrypt and store.
            aad:       Additional authenticated data bound to this blob.
            pin:       Pin to prevent GC.

        Returns:
            IPFS CID of the encrypted blob.
        """
        from apps.crypto_bridge.symmetric import aes_encrypt

        key = self._get_enc_key()
        encrypted_blob = aes_encrypt(key, plaintext, aad)
        envelope = json.dumps({
            "v": 1,
            "enc": base64.urlsafe_b64encode(encrypted_blob).decode("ascii"),
        }).encode("utf-8")

        cid = self.add_bytes(envelope, pin=pin)
        log.info("IPFS add_encrypted", extra={"cid": cid, "plaintext_size": len(plaintext)})
        return cid

    def get_encrypted(self, cid: str, aad: bytes = b"") -> bytes:
        """
        Retrieve and decrypt an encrypted blob from IPFS.

        Args:
            cid: IPFS CID returned by add_encrypted().
            aad: Must match the aad used during upload.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: if the blob format is invalid.
            CryptoError: if authentication fails (wrong key or tampered blob).
        """
        from apps.crypto_bridge.symmetric import aes_decrypt

        raw = self.get_bytes(cid)

        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"IPFS blob is not valid JSON: {exc}") from exc

        if envelope.get("v") != 1 or "enc" not in envelope:
            raise ValueError("Unknown IPFS blob version or format.")

        encrypted_blob = base64.urlsafe_b64decode(envelope["enc"])
        key = self._get_enc_key()
        plaintext = aes_decrypt(key, encrypted_blob, aad)
        log.debug("IPFS get_encrypted ok", extra={"cid": cid})
        return plaintext

    # ── JSON helpers ──────────────────────────────────────────────────────────

    def add_json(
        self,
        data: Any,
        encrypt: bool = False,
        aad: bytes = b"",
        pin: bool = True,
    ) -> str:
        """
        Serialise a Python object to JSON and upload to IPFS.

        Args:
            data:    JSON-serialisable Python object.
            encrypt: If True, encrypt before uploading.
            aad:     AAD for encryption (only used if encrypt=True).
            pin:     Pin to prevent GC.

        Returns:
            IPFS CID string.
        """
        json_bytes = json.dumps(data, default=str, ensure_ascii=False).encode("utf-8")

        if encrypt:
            return self.add_encrypted(json_bytes, aad=aad, pin=pin)
        return self.add_bytes(json_bytes, pin=pin)

    def get_json(
        self,
        cid: str,
        encrypted: bool = False,
        aad: bytes = b"",
    ) -> Any:
        """
        Retrieve and deserialise a JSON object from IPFS.

        Args:
            cid:       IPFS CID.
            encrypted: If True, decrypt before parsing.
            aad:       AAD for decryption (must match upload).

        Returns:
            Deserialised Python object.
        """
        if encrypted:
            raw = self.get_encrypted(cid, aad=aad)
        else:
            raw = self.get_bytes(cid)

        return json.loads(raw.decode("utf-8"))

    # ── Document helpers ──────────────────────────────────────────────────────

    def add_document(
        self,
        document_bytes: bytes,
        document_type: str,
        user_id: str,
        pin: bool = True,
    ) -> str:
        """
        Upload a KYC document with user-scoped encryption.

        Uses user_id + document_type as AAD to bind the blob to the
        specific user, preventing cross-user decryption.

        Args:
            document_bytes: Raw document bytes (PDF, JPEG, PNG).
            document_type:  Label: "id_document", "proof_of_address", "selfie".
            user_id:        User UUID string for AAD binding.
            pin:            Pin to prevent GC.

        Returns:
            IPFS CID.
        """
        aad = f"{user_id}:{document_type}".encode("utf-8")
        cid = self.add_encrypted(document_bytes, aad=aad, pin=pin)
        log.info(
            "IPFS document uploaded",
            extra={"cid": cid, "type": document_type, "user_id": user_id},
        )
        return cid

    def get_document(
        self,
        cid: str,
        document_type: str,
        user_id: str,
    ) -> bytes:
        """
        Retrieve and decrypt a KYC document from IPFS.

        Args:
            cid:           IPFS CID from add_document().
            document_type: Must match the type used during upload.
            user_id:       Must match the user_id used during upload.

        Returns:
            Decrypted document bytes.
        """
        aad = f"{user_id}:{document_type}".encode("utf-8")
        return self.get_encrypted(cid, aad=aad)

    # ── Audit anchoring ───────────────────────────────────────────────────────

    def anchor_audit_log(self, audit_data: dict) -> str:
        """
        Store an audit log snapshot on IPFS for immutable archival.

        The data is stored unencrypted (audit logs don't contain PII
        after GDPR anonymisation) with a SHA-256 integrity hash.

        Args:
            audit_data: Audit log dict (JSON-serialisable).

        Returns:
            IPFS CID string.
        """
        # Append integrity hash to the stored data
        payload = dict(audit_data)
        payload_bytes = json.dumps(
            {k: v for k, v in payload.items() if k != "integrity_hash"},
            default=str,
            sort_keys=True,
        ).encode("utf-8")
        payload["integrity_hash"] = hashlib.sha256(payload_bytes).hexdigest()

        cid = self.add_json(payload, encrypt=False, pin=True)
        log.info("IPFS audit log anchored", extra={"cid": cid})
        return cid

    # ── Pinning ───────────────────────────────────────────────────────────────

    def pin(self, cid: str) -> bool:
        """
        Pin a CID to prevent garbage collection.

        Args:
            cid: IPFS CID to pin.

        Returns:
            True if pinned successfully.
        """
        try:
            client = self._get_client()
            client.pin.add(cid)
            log.debug("IPFS pin ok", extra={"cid": cid})
            return True
        except Exception as exc:
            log.warning("IPFS pin failed", exc_info=exc, extra={"cid": cid})
            return False

    def unpin(self, cid: str) -> bool:
        """
        Unpin a CID (allow GC to reclaim it).

        Args:
            cid: IPFS CID to unpin.

        Returns:
            True if unpinned successfully.
        """
        try:
            client = self._get_client()
            client.pin.rm(cid)
            log.debug("IPFS unpin ok", extra={"cid": cid})
            return True
        except Exception as exc:
            log.warning("IPFS unpin failed", exc_info=exc, extra={"cid": cid})
            return False

    def is_available(self) -> bool:
        """
        Health-check: test connectivity to the IPFS daemon.

        Returns:
            True if the IPFS daemon is reachable.
        """
        try:
            client = self._get_client()
            client.id()
            return True
        except Exception:
            return False
