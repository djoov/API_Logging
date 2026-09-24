"""Phase 3 interface tests (encryption is not used by the Phase 1 server/client yet)."""
from __future__ import annotations

from pathlib import Path

import pytest

from security.payload_crypto import (
    PayloadCryptoError,
    decrypt_payload,
    encrypt_payload,
    generate_key,
    load_key,
)

PAYLOAD = {"message": "hello from kali", "sender": "kali", "sequence": 1}


def test_round_trip_with_legitimate_key() -> None:
    key = generate_key()
    token = encrypt_payload(PAYLOAD, key)
    assert "hello" not in token
    assert decrypt_payload(token, key) == PAYLOAD


def test_wrong_key_fails() -> None:
    token = encrypt_payload(PAYLOAD, generate_key())
    with pytest.raises(PayloadCryptoError):
        decrypt_payload(token, generate_key())


def test_tampered_token_fails() -> None:
    key = generate_key()
    token = encrypt_payload(PAYLOAD, key)
    tampered = token[:-5] + ("A" if token[-5] != "A" else "B") + token[-4:]
    with pytest.raises(PayloadCryptoError):
        decrypt_payload(tampered, key)


def test_invalid_key_rejected() -> None:
    with pytest.raises(PayloadCryptoError):
        encrypt_payload(PAYLOAD, b"too-short")


def test_load_key_from_env_and_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = generate_key()
    monkeypatch.setenv("FERNET_KEY", key.decode())
    assert load_key() == key

    monkeypatch.delenv("FERNET_KEY")
    secret = tmp_path / "fernet.key"
    secret.write_text(key.decode() + "\n", encoding="ascii")
    monkeypatch.setenv("FERNET_KEY_FILE", str(secret))
    assert load_key() == key

    monkeypatch.delenv("FERNET_KEY_FILE")
    with pytest.raises(PayloadCryptoError):
        load_key()
