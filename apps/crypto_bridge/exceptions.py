"""
apps/crypto_bridge/exceptions.py
Single exception type surfaced by the crypto bridge layer.
"""


class CryptoError(Exception):
    """
    Raised when any cryptographic operation in the C++ engine fails.

    Wraps RuntimeError, ValueError, and all other exceptions from
    blackpay_crypto so callers only need to catch one type.
    """
