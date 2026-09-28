"""Phase 3/4 tests: application-layer (Fernet) payload encryption and authorized decryption."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from client.traffic_generator import build_payload, build_secure_body, send_one
from common.config import Settings
from models.schemas import new_request_id
from observer.capture_backend import CaptureRecord
from observer.correlator import ExchangeCorrelator
from security.payload_crypto import decrypt_payload, encrypt_payload, generate_key, key_id, write_key_file
from server.api_server import create_app

KEY = generate_key()
OTHER_KEY = generate_key()


def server_records(settings: Settings) -> list[dict[str, Any]]:
    path = settings.log_dir / "server-events.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def envelope(message: str = "rahasia dari kali", key: bytes = KEY) -> dict[str, Any]:
    return build_secure_body(build_payload("kali", 1, message), key)


# ---- key handling --------------------------------------------------------

def test_key_id_is_stable_and_does_not_reveal_the_key() -> None:
    assert key_id(KEY) == key_id(KEY.decode()) and len(key_id(KEY)) == 12
    assert key_id(KEY) != key_id(OTHER_KEY)
    assert key_id(KEY) not in KEY.decode()


def test_write_key_file_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "fernet.key"
    write_key_file(path)
    with pytest.raises(FileExistsError):
        write_key_file(path)


def test_envelope_keeps_metadata_clear_and_message_secret() -> None:
    body = envelope("pesan rahasia")
    assert body["enc"] == "fernet" and body["key_id"] == key_id(KEY)
    assert body["sender"] == "kali" and body["sequence"] == 1 and body["request_id"]
    assert "pesan rahasia" not in json.dumps(body)
    assert decrypt_payload(body["ciphertext"], KEY) == {"message": "pesan rahasia"}


# ---- Test D: server holds the key (authorized decryption point) ------------

def test_authorized_server_decrypts_and_replies_encrypted(settings: Settings) -> None:
    client = TestClient(create_app(settings, app_key=KEY))
    response = client.post("/api/secure-test", json=envelope("rahasia dari kali"))
    assert response.status_code == 200
    data = response.json()
    assert data["decryption_status"] == "authorized" and data["message"] == "received"
    assert "rahasia" not in response.text  # the reply payload is encrypted too
    assert decrypt_payload(data["ciphertext"], KEY) == {"message": "received", "received_chars": 17}

    [record] = server_records(settings)
    assert record["decryption_status"] == "authorized" and record["app_encryption"] == "fernet"
    assert record["payload"]["message"] == "rahasia dari kali"  # visible only to the key holder
    assert record["key_id"] == key_id(KEY) and record["ciphertext_bytes"] > 0


# ---- Test C: server without the key --------------------------------------

def test_server_without_key_accepts_but_cannot_read(settings: Settings) -> None:
    client = TestClient(create_app(settings, app_key=None))
    response = client.post("/api/secure-test", json=envelope("rahasia dari kali"))
    assert response.status_code == 200
    data = response.json()
    assert data["decryption_status"] == "not_authorized" and "ciphertext" not in data
    [record] = server_records(settings)
    assert record["decryption_status"] == "not_authorized"
    assert record["payload"]["message"] is None and "rahasia" not in json.dumps(record)
    assert record["request_id"] and record["payload"]["sequence"] == 1  # routing metadata stays visible


# ---- failures -------------------------------------------------------------

def test_wrong_key_is_rejected_and_logged_as_failed(settings: Settings) -> None:
    client = TestClient(create_app(settings, app_key=KEY))
    response = client.post("/api/secure-test", json=envelope(key=OTHER_KEY))
    assert response.status_code == 400 and "decryption failed" in response.text
    [record] = server_records(settings)
    assert record["decryption_status"] == "failed" and record["payload"]["message"] is None


def test_tampered_ciphertext_is_rejected(settings: Settings) -> None:
    body = envelope()
    token = body["ciphertext"]
    body["ciphertext"] = token[:-6] + ("A" if token[-6] != "A" else "B") + token[-5:]
    response = TestClient(create_app(settings, app_key=KEY)).post("/api/secure-test", json=body)
    assert response.status_code == 400


def test_plain_endpoint_unchanged(settings: Settings) -> None:
    client = TestClient(create_app(settings, app_key=KEY))
    body = build_payload("kali", 1).model_dump(mode="json")
    assert client.post("/api/test", json=body).status_code == 200
    [record] = server_records(settings)
    assert record.get("decryption_status") is None and record.get("app_encryption") is None


# ---- client end to end -----------------------------------------------------

def test_client_encrypts_and_decrypts_reply(settings: Settings) -> None:
    client = TestClient(create_app(settings, app_key=KEY))
    result = send_one(client, "http://testserver", build_payload("kali", 1, "halo aman"), 0, 0, app_key=KEY)
    assert result.ok and result.endpoint == "/api/secure-test"
    assert result.decryption_status == "authorized"
    assert result.reply_plaintext == {"message": "received", "received_chars": 9}
    assert result.app_encryption == "fernet" and result.key_id == key_id(KEY)


# ---- observer --------------------------------------------------------------

def test_correlator_carries_security_fields_from_logs() -> None:
    rid = new_request_id()
    corr = ExchangeCorrelator("windows", merge_window=0)
    corr.add_client_record({"record_type": "client_exchange", "request_id": rid, "sent_at": "2026-09-28T05:00:00.000Z",
                            "sender": "kali", "status_code": 200, "app_encryption": "fernet", "key_id": "abc",
                            "ciphertext_bytes": 140, "decryption_status": "authorized",
                            "payload": {"message": "rahasia", "sender": "kali", "sequence": 1}})
    corr.add_server_record({"record_type": "server_exchange", "request_id": rid, "received_at": "2026-09-28T05:00:00.010Z",
                            "receiver": "windows", "status_code": 200, "app_encryption": "fernet", "key_id": "abc",
                            "ciphertext_bytes": 140, "decryption_status": "authorized"})
    [event] = corr.flush(force=True)
    assert (event["app_encryption"], event["decryption_status"], event["key_id"]) == ("fernet", "authorized", "abc")
    assert event["payload"]["message"] == "rahasia"


def test_plaintext_capture_sees_envelope_but_not_message() -> None:
    body = envelope("rahasia di kabel")
    rid = body["request_id"]
    corr = ExchangeCorrelator("third-host", merge_window=0)
    wire_body = {k: str(v) for k, v in body.items()}  # TShark json.member_with_value gives strings
    corr.add_capture_record(CaptureRecord(kind="request", timestamp=1.0, backend="t", method="POST",
                                          uri="/api/secure-test", headers={"x-request-id": rid}, body=wire_body))
    corr.add_capture_record(CaptureRecord(kind="response", timestamp=1.01, backend="t", status_code=200,
                                          headers={"x-request-id": rid}))
    [event] = corr.flush(force=True)
    assert event["app_encryption"] == "fernet" and event["key_id"] == key_id(KEY)
    assert event["ciphertext_bytes"] == len(body["ciphertext"])
    assert event["payload"]["message"] is None  # network observer: encrypted state visible, content not
    assert event["decryption_status"] is None


def test_encrypt_payload_roundtrip_with_sent_at_unaffected() -> None:
    token = encrypt_payload({"message": "x", "at": datetime.now(timezone.utc).isoformat()}, KEY)
    assert decrypt_payload(token, KEY)["message"] == "x"
