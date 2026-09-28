"""PHASE 3/4: application-layer payload encryption (Fernet) and authorized decryption.

    plaintext dict -> encrypt_payload() -> envelope {"enc": "fernet", "key_id", "ciphertext"} over HTTPS
    -> TLS terminates at the server -> decrypt_payload() by the holder of the key -> original dict

Fernet = AES-128-CBC + HMAC-SHA256 with a timestamp: confidentiality AND integrity, so a wrong key
or a tampered token fails loudly (PayloadCryptoError) instead of producing garbage.

Keys are never stored in source code. They come from FERNET_KEY (the key itself) or from a local
secret file (FERNET_KEY_FILE, e.g. secrets/fernet.key, kept out of version control). key_id() is a
short fingerprint so both hosts can confirm they hold the same key without revealing it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

ALGORITHM = "fernet"


class PayloadCryptoError(ValueError):
    """Key missing/invalid, or ciphertext cannot be decrypted with the given key."""


def generate_key() -> bytes:
    return Fernet.generate_key()


def key_id(key: bytes | str) -> str:
    """Public fingerprint of a key (first 12 hex chars of SHA-256). Safe to log; not the key."""
    raw = key.encode("ascii") if isinstance(key, str) else key
    return hashlib.sha256(raw.strip()).hexdigest()[:12]


def write_key_file(path: Path) -> bytes:
    """Create a new key file. Refuses to overwrite: replacing a key breaks the other host."""
    if path.exists():
        raise FileExistsError(f"{path} already exists; delete it explicitly to replace the key")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_key()
    path.write_bytes(key + b"\n")
    if os.name == "posix":
        path.chmod(0o600)
    return key


def load_key(key_file: Path | None = None) -> bytes:
    """Load the key from FERNET_KEY, else from key_file, else from the file named by FERNET_KEY_FILE."""
    key = os.getenv("FERNET_KEY", "").strip()
    if not key:
        if key_file is None:
            env_file = os.getenv("FERNET_KEY_FILE", "").strip()
            if not env_file:
                raise PayloadCryptoError("set FERNET_KEY or FERNET_KEY_FILE")
            key_file = Path(env_file)
        if not key_file.is_file():
            raise PayloadCryptoError(f"FERNET_KEY_FILE not found: {key_file}")
        key = key_file.read_text(encoding="ascii").strip()
    _fernet(key)  # validate format early
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
