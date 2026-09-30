"""scripts/show_evidence.py: per-host evidence summary and the plaintext-on-the-wire check."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import show_evidence  # noqa: E402


def write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def gateway_record(rid: str, prompt: str) -> dict[str, Any]:
    return {"record_type": "llm_gateway_exchange", "request_id": rid, "received_at": "2026-09-28T12:00:00Z",
            "sender": "kali", "receiver": "windows", "method": "POST", "endpoint": "/api/generate",
            "http_path": "/secure/api/generate", "transport": "https", "status_code": 200,
            "app_encryption": "fernet", "key_id": "80dacc3b5d23", "ciphertext_bytes": 184,
            "decryption_status": "authorized", "reply_encrypted_lines": 31, "reply_ciphertext_bytes": 9462,
            "payload": {"message": prompt, "sender": "kali"},
            "llm": {"prompt": prompt, "response": "jawaban rahasia yang cukup panjang untuk diperiksa"}}


def test_encrypted_exchange_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "server-events.jsonl", [gateway_record("a" * 36, "prompt yang dirahasiakan")])
    write(tmp_path / "capture-events.jsonl", [
        {"kind": "tls_client_hello", "dst_port": 8443, "src_port": 50000},
        {"kind": "tls_app_data", "src_port": 8443, "dst_port": 50000, "tls_bytes": 314},
        {"kind": "tls_app_data", "src_port": 8443, "dst_port": 50000, "tls_bytes": 290},
    ])
    assert show_evidence.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "decrypted here      : authorized" in out
    assert "reply sent encrypted: 31 lines, 9462 B" in out
    assert "found in the capture: NO" in out
    assert "314 B x1" in out


def test_plaintext_on_the_wire_is_flagged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "server-events.jsonl", [gateway_record("b" * 36, "hello from windows #1")])
    write(tmp_path / "capture-events.jsonl", [
        {"kind": "request", "src_port": 50000, "dst_port": 8000, "body": {"message": "hello from windows #1"}},
    ])
    assert show_evidence.main([str(tmp_path)]) == 0
    assert "YES - plaintext on the wire!" in capsys.readouterr().out


def test_network_view_only_covers_the_requests_shown(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A log folder holds several test runs; the sizes of an old run must not be mixed in (Kali, 2026-09-28).
    old, new = gateway_record("c" * 36, "uji lama sekali"), gateway_record("d" * 36, "uji baru sekali")
    old["received_at"], old["completed_at"] = "2026-09-24T12:00:00Z", "2026-09-24T12:00:02Z"
    new["received_at"], new["completed_at"] = "2026-09-28T12:00:00Z", "2026-09-28T12:00:02Z"
    write(tmp_path / "server-events.jsonl", [old, new])
    t_old, t_new = 1790251201.0, 1790596801.0  # epoch seconds inside each run
    write(tmp_path / "capture-events.jsonl", [
        {"kind": "tls_app_data", "src_port": 8443, "tls_bytes": 999, "timestamp": t_old},
        {"kind": "tls_app_data", "src_port": 8443, "tls_bytes": 314, "timestamp": t_new},
    ])
    assert show_evidence.main([str(tmp_path), "--last", "1"]) == 0
    out = capsys.readouterr().out
    assert "314 B x1" in out and "999 B" not in out and "limited to 1 of 2" in out


def test_empty_folder(tmp_path: Path) -> None:
    assert show_evidence.main([str(tmp_path)]) == 1
