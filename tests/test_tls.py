"""Phase 2 (HTTPS/TLS) tests: certificates, real TLS client/server, TLS capture parsing and correlation."""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn
from cryptography import x509

from client.traffic_generator import build_payload, build_verify, send_one
from common.config import Settings
from observer.capture_backend import CaptureRecord, TsharkBackend
from observer.correlator import ExchangeCorrelator
from observer.tls_flows import TlsExchangeTracker
from security.tls_certs import create_ca, create_server_cert
from server.api_server import create_app

FIXTURES = Path(__file__).parent / "fixtures"


# ---- certificates ------------------------------------------------------

@pytest.fixture
def certs(tmp_path: Path) -> Path:
    create_ca(tmp_path)
    create_server_cert(tmp_path, tmp_path, "local", ["127.0.0.1"], ["localhost"])
    return tmp_path


def test_server_cert_lists_ips_and_is_signed_by_ca(certs: Path) -> None:
    cert = x509.load_pem_x509_certificate((certs / "local.pem").read_bytes())
    ca = x509.load_pem_x509_certificate((certs / "ca.pem").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert cert.issuer == ca.subject
    cert.verify_directly_issued_by(ca)  # raises if the signature does not verify


def test_create_ca_refuses_to_overwrite(certs: Path) -> None:
    with pytest.raises(FileExistsError):
        create_ca(certs)


def test_server_cert_needs_an_address(certs: Path) -> None:
    with pytest.raises(ValueError):
        create_server_cert(certs, certs, "empty", [], [])


def test_build_verify(certs: Path, tmp_path: Path) -> None:
    assert build_verify("http://127.0.0.1:8000", None) is True
    assert build_verify("https://127.0.0.1:8000", certs / "ca.pem") is not True
    with pytest.raises(FileNotFoundError):
        build_verify("https://127.0.0.1:8000", tmp_path / "missing.pem")


# ---- real HTTPS server -------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def https_server(settings: Settings, certs: Path) -> Iterator[str]:
    port = _free_port()
    config = uvicorn.Config(create_app(replace(settings, node_name="kali")), host="127.0.0.1", port=port,
                            ssl_certfile=str(certs / "local.pem"), ssl_keyfile=str(certs / "local.key"),
                            log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started, "HTTPS test server did not start"
    yield f"https://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def test_https_request_with_lab_ca(https_server: str, certs: Path, settings: Settings) -> None:
    with httpx.Client(verify=build_verify(https_server, certs / "ca.pem"), timeout=5) as client:
        result = send_one(client, https_server, build_payload("windows", 1), retries=0, retry_backoff=0)
    assert result.ok and result.receiver == "kali"
    assert result.tls_version in ("TLSv1.2", "TLSv1.3") and result.tls_cipher
    [record] = [json.loads(line) for line in (settings.log_dir / "server-events.jsonl").read_text().splitlines()]
    assert record["transport"] == "https"


def test_https_rejects_untrusted_certificate(https_server: str) -> None:
    # System trust store does not contain the lab CA: verification must fail, not be skipped.
    with httpx.Client(verify=True, timeout=5) as client:
        result = send_one(client, https_server, build_payload("windows", 1), retries=0, retry_backoff=0)
    assert not result.ok and result.error and "TLS certificate rejected" in result.error


def test_https_rejects_certificate_for_other_ip(settings: Settings, tmp_path: Path) -> None:
    create_ca(tmp_path)
    create_server_cert(tmp_path, tmp_path, "other", ["192.0.2.10"])  # not 127.0.0.1
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port,
                                           ssl_certfile=str(tmp_path / "other.pem"),
                                           ssl_keyfile=str(tmp_path / "other.key"), log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        while not server.started:
            time.sleep(0.05)
        target = f"https://127.0.0.1:{port}"
        with httpx.Client(verify=build_verify(target, tmp_path / "ca.pem"), timeout=5) as client:
            result = send_one(client, target, build_payload("windows", 1), retries=0, retry_backoff=0)
        assert not result.ok and "TLS certificate rejected" in (result.error or "")
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_plain_http_to_https_server_fails_clearly(https_server: str) -> None:
    target = https_server.replace("https://", "http://")
    with httpx.Client(timeout=5) as client:
        result = send_one(client, target, build_payload("windows", 1), retries=0, retry_backoff=0)
    assert not result.ok


# ---- TLS capture parsing (real TShark 4.6 output, HTTPS on loopback) -----

def tls_records() -> list[CaptureRecord]:
    lines = (FIXTURES / "tshark_tls_sample.tsv").read_text(encoding="utf-8").splitlines()
    return [r for r in (TsharkBackend.parse_line(line) for line in lines) if r is not None]


def test_tls_capture_hides_http_details() -> None:
    records = tls_records()
    kinds = [r.kind for r in records]
    assert kinds[:3] == ["tls_client_hello", "tls_server_hello", "tls_handshake"]
    assert set(kinds[3:]) == {"tls_app_data"}
    hello = records[1]
    assert hello.tls_version == "TLSv1.3" and hello.tls_cipher == "TLS_AES_256_GCM_SHA384"
    assert records[0].tls_sni is None  # client connected to an IP, so no SNI
    for r in records:
        assert r.method is None and r.uri is None and r.status_code is None and r.request_id is None


def test_tls_tracker_rebuilds_exchanges() -> None:
    tracker = TlsExchangeTracker(server_port=8765)
    finished = []
    for r in tls_records():
        finished += tracker.add(r)
    finished += tracker.expire(0, 0, force=True)
    assert len(finished) == 3  # GET /health + 2x POST /api/test
    assert tracker.ignored_server_records == 1  # TLS 1.3 session tickets before the first request
    health, post1, post2 = finished
    assert post1.request_bytes == 290 + 172  # headers and body in two records
    assert post1.response_bytes == 243 + 208
    assert all(ex.wire_latency_ms and ex.wire_latency_ms > 0 for ex in finished)
    assert post1.tls_version == "TLSv1.3"


def _replay_capture(name: str) -> list[CaptureRecord]:
    records = []
    for data in _load(name):
        data.pop("request_id", None)  # derived property, not a constructor field
        records.append(CaptureRecord(**data))
    return records


def test_session_ticket_after_first_request_is_not_the_response() -> None:
    # Real live capture: the TLS 1.3 session ticket (500 B) arrived AFTER the /health request.
    # Regression: it used to be taken as the response, giving a 0.06 ms wire latency.
    records = _replay_capture("tls_ticket_after_request.jsonl")
    corr = ExchangeCorrelator("local-server", merge_window=0, server_port=8765)
    for rec in _load("tls_ticket_client_events.jsonl"):
        corr.add_client_record(rec)
    for rec in _load("tls_ticket_server_events.jsonl"):
        corr.add_server_record(rec)
    for rec in records:
        corr.add_capture_record(rec)
    events = corr.flush(force=True)

    assert len(events) == 4 and all(e["capture_match"] == "4tuple_time" for e in events)
    for event in events:
        # Wire time at the server host always includes the server's own processing time.
        assert event["wire_latency_ms"] >= event["server_processing_ms"], event
    [health] = [e for e in events if e["endpoint"] == "/health"]
    assert health["response_bytes"] == 249 + 32  # the 500-byte ticket is excluded


def test_tls_tracker_ignores_alert_sized_client_records() -> None:
    tracker = TlsExchangeTracker(server_port=8000)
    rec = CaptureRecord(kind="tls_app_data", timestamp=1.0, backend="t", src_ip="10.0.0.1", src_port=5000,
                        dst_ip="10.0.0.2", dst_port=8000, tls_bytes=19)
    tracker.add(rec)
    assert tracker.in_progress() == []


def _load(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines()]


def test_correlator_matches_tls_by_4tuple_and_time() -> None:
    corr = ExchangeCorrelator("probe", merge_window=0, server_port=8765)
    for rec in _load("tls_client_events.jsonl"):
        corr.add_client_record(rec)
    for rec in _load("tls_server_events.jsonl"):
        corr.add_server_record(rec)
    for rec in tls_records():
        corr.add_capture_record(rec)
    events = corr.flush(force=True)

    assert len(events) == 3, [e["evidence"] for e in events]
    for event in events:
        assert "capture_tls" in event["evidence"]
        assert event["capture_match"] == "4tuple_time"
        assert event["transport"] == "https" and event["tls_version"] == "TLSv1.3"
        assert event["request_id"]  # comes from the app logs, never from the wire
        assert event["wire_latency_ms"] > 0
    posts = sorted((e for e in events if e["endpoint"] == "/api/test"), key=lambda e: e["payload"]["sequence"])
    assert [e["request_bytes"] for e in posts] == [462, 462]
    assert all(e["client_rtt_ms"] >= e["server_processing_ms"] for e in posts)


def test_tls_without_app_logs_is_capture_only() -> None:
    corr = ExchangeCorrelator("third-host", {"127.0.0.1": "local"}, merge_window=0, server_port=8765)
    for rec in tls_records():
        corr.add_capture_record(rec)
    events = corr.flush(force=True)
    assert len(events) == 3
    for event in events:
        assert event["evidence"] == ["capture_tls"]
        assert event["request_id"] is None and event["method"] is None and event["status_code"] is None
        assert event["capture_match"] is None and event["transport"] == "https"
        assert event["direction"] == "local_to_local"


def test_plaintext_events_report_request_id_match() -> None:
    lines = (FIXTURES / "tshark_fields_sample.tsv").read_text(encoding="utf-8").splitlines()
    corr = ExchangeCorrelator("probe", merge_window=0)
    for record in filter(None, (TsharkBackend.parse_line(line) for line in lines)):
        corr.add_capture_record(record)
    events = corr.flush(force=True)
    assert {e["capture_match"] for e in events} == {"request_id"}
    assert {e["transport"] for e in events} == {"http"}
