"""PHASE 3 preparation: application-layer payload encryption with Fernet.

NOT wired into the server/client yet. Phase 1 (plaintext HTTP) must be stable first.

Flow in Phase 3:
    plaintext dict -> encrypt_payload() -> {"ciphertext": "..."} over HTTPS
    -> TLS terminates at the server -> decrypt_payload() with the shared key -> original dict

Keys are never stored in source code. They come from the FERNET_KEY environment variable
or from a local secret file named by FERNET_KEY_FILE (keep it out of version control).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class PayloadCryptoError(ValueError):
    """Key missing/invalid, or ciphertext cannot be decrypted with the given key."""


def generate_key() -> bytes:
    return Fernet.generate_key()


def load_key() -> bytes:
    """Load the key from FERNET_KEY, or from the file named by FERNET_KEY_FILE."""
    key = os.getenv("FERNET_KEY", "").strip()
    if not key:
        key_file = os.getenv("FERNET_KEY_FILE", "").strip()
        if not key_file:
            raise PayloadCryptoError("set FERNET_KEY or FERNET_KEY_FILE")
        path = Path(key_file)
        if not path.is_file():
            raise PayloadCryptoError(f"FERNET_KEY_FILE not found: {path}")
        key = path.read_text(encoding="ascii").strip()
    return key.encode("ascii")


def _fernet(key: bytes | str) -> Fernet:
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise PayloadCryptoError("invalid Fernet key (expected 32 url-safe base64-encoded bytes)") from exc


def encrypt_payload(payload: dict[str, Any], key: bytes | str) -> str:
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _fernet(key).encrypt(plaintext).decode("ascii")


def decrypt_payload(ciphertext: str, key: bytes | str, ttl_seconds: int | None = None) -> dict[str, Any]:
    """Decrypt with the legitimate key. Fails loudly on a wrong key or tampered token."""
    try:
        plaintext = _fernet(key).decrypt(ciphertext.encode("ascii"), ttl=ttl_seconds)
    except InvalidToken as exc:
        raise PayloadCryptoError("decryption failed: wrong key, expired or tampered ciphertext") from exc
    return json.loads(plaintext)
