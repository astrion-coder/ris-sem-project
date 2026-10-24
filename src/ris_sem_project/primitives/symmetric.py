"""Symmetric encryption (Definition 14), instantiated as AES-256-GCM.

Blob layout: nonce (12 random bytes) || ciphertext || tag (16 bytes).
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def aes_key(material: bytes) -> bytes:
    """AES-256 key: the first 256 bits of a derived key string."""
    if len(material) < KEY_SIZE:
        raise ValueError(f"need at least {KEY_SIZE} bytes of key material, got {len(material)}")
    return bytes(material[:KEY_SIZE])


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Enc(key, m) = nonce || ciphertext || tag."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, blob: bytes) -> bytes | None:
    """Dec(key, blob), or None if the blob is too short or the tag fails.

    A wrong key is an expected outcome while scanning in Retrieve, so it is a
    return value, not an exception.
    """
    if len(key) != KEY_SIZE or len(blob) < NONCE_SIZE + TAG_SIZE:
        return None
    try:
        return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], None)
    except InvalidTag:
        return None
