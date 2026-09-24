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


def test_tcp_nodelay_listener_reaches_accepted_connections(settings: Settings, certs: Path,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio.base_events as base_events

    from server.api_server import _listening_socket

    seen: list[int] = []
    original = base_events._set_nodelay

    def spy(sock: socket.socket) -> None:
        original(sock)
        seen.append(sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))

    monkeypatch.setattr(base_events, "_set_nodelay", spy)
    port = _free_port()
    listener = _listening_socket("127.0.0.1", port, tcp_nodelay=True)
    server = uvicorn.Server(uvicorn.Config(create_app(settings), log_level="warning", timeout_keep_alive=10,
                                           ssl_certfile=str(certs / "local.pem"),
                                           ssl_keyfile=str(certs / "local.key")))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        while not server.started:
            time.sleep(0.05)
        target = f"https://127.0.0.1:{port}"
        with httpx.Client(verify=build_verify(target, certs / "ca.pem"), timeout=5) as client:
            assert send_one(client, target, build_payload("kali", 1), retries=0, retry_backoff=0).ok
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    assert seen and all(value != 0 for value in seen)  # Nagle is off on the accepted connection


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


def test_real_two_host_session_has_no_phantom_exchanges() -> None:
    # Real Windows<->Kali HTTPS session over the Host-Only link (MTU 1500), seen from Windows.
    # Regression: on a real NIC the server's encrypted handshake tail arrives in its own frame;
    # it used to be taken for the session ticket, so the real ticket became a "response",
    # splitting requests into phantom exchanges and giving wire < server processing.
    corr = ExchangeCorrelator("windows", {"192.168.56.1": "windows", "192.168.56.10": "kali"},
                              merge_window=0, server_port=8000)
    for rec in _load("twohost_tls_client.jsonl"):
        corr.add_client_record(rec)
    for rec in _load("twohost_tls_server.jsonl"):
        corr.add_server_record(rec)
    for rec in _replay_capture("twohost_tls_capture.jsonl"):
        corr.add_capture_record(rec)
    events = [e for e in corr.flush(force=True) if "capture_tls" in e["evidence"]]

    capture_only = [e for e in events if e["evidence"] == ["capture_tls"]]
    assert len(events) == 12 and len(capture_only) == 1  # only the client's /health to Kali has no app log
    assert capture_only[0]["direction"] == "windows_to_kali"
    for e in events:
        if e["vantage"] == "server_side":
            assert e["wire_latency_ms"] >= e["server_processing_ms"], e
        if e["vantage"] == "client_side" and e["client_rtt_ms"] is not None:
            assert e["wire_latency_ms"] <= e["client_rtt_ms"], e
    posts = [e for e in events if e["endpoint"] == "/api/test"]
    assert len(posts) == 10
    assert {e["request_bytes"] for e in posts} == {472}  # headers + body, never split

    # Kali request #1: response headers left Windows after ~3.9 ms but the body only ~48 ms
    # after the request (Kali's own client measured 49.2 ms). wire_latency_ms must cover the
    # whole response; the first-byte time is kept separately.
    [first] = [e for e in posts if e["request_id"] == "edd0a90b-48cf-416e-a18e-503acd14d602"]
    assert abs(first["wire_ttfb_ms"] - 3.92) < 0.1
    assert abs(first["wire_latency_ms"] - 47.93) < 0.1


def test_unlogged_exchange_does_not_steal_next_requests_log() -> None:
    # Real Kali-side bug: /health (no app log on the client host) and POST #1 share one
    # keep-alive connection. /health finished first and grabbed POST #1's log entry, so POST #1
    # itself became a "capture-only" exchange. Reproduced incrementally with the real records
    # of that connection (Windows capture, stream 5), keeping only POST #1's app log.
    records = [r for r in _replay_capture("twohost_tls_capture.jsonl") if r.tcp_stream == 5]
    post1_log = [r for r in _load("twohost_tls_server.jsonl")
                 if r["request_id"] == "edd0a90b-48cf-416e-a18e-503acd14d602"]
    corr = ExchangeCorrelator("windows", merge_window=60, server_port=8000)

    first_response_part = next(i for i, r in enumerate(records) if r.tls_bytes == 245)
    for rec in records[:first_response_part]:  # /health done, POST #1 request in progress
        corr.add_capture_record(rec)
    corr.add_server_record(post1_log[0])
    assert corr.flush() == []  # nothing is due yet, and /health must not claim POST #1's log
    for rec in records[first_response_part:]:
        corr.add_capture_record(rec)
    events = corr.flush(force=True)

    [post] = [e for e in events if e["request_id"]]
    [health] = [e for e in events if not e["request_id"]]
    assert post["request_bytes"] == 472 and abs(post["wire_latency_ms"] - 47.93) < 0.1
    assert health["request_bytes"] == 246 and health["evidence"] == ["capture_tls"]


def test_cold_start_request_is_matched_by_causality_not_nearest_time() -> None:
    # Real Run C (Windows server, TCP_NODELAY): the first request after a server restart reached
    # the middleware ~19 ms after it hit the wire, so its log time was closer to the NEXT request
    # on the same connection. Nearest-time matching swapped /health and POST #1.
    corr = ExchangeCorrelator("windows", merge_window=0, server_port=8000)
    for rec in _load("runc_cold_start_server.jsonl"):
        corr.add_server_record(rec)
    for rec in _replay_capture("runc_cold_start_capture.jsonl"):
        corr.add_capture_record(rec)
    events = corr.flush(force=True)

    assert len(events) == 6 and all(e["capture_match"] == "4tuple_time" for e in events)
    [health] = [e for e in events if e["endpoint"] == "/health"]
    assert (health["request_bytes"], health["response_bytes"]) == (246, 276)
    for post in (e for e in events if e["endpoint"] == "/api/test"):
        assert (post["request_bytes"], post["response_bytes"]) in {(472, 455), (472, 454)}
        assert post["wire_latency_ms"] >= post["server_processing_ms"]


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
