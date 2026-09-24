from __future__ import annotations

import logging
from pathlib import Path

from common.jsonl import JsonlTailer, append_jsonl
from models.schemas import new_request_id
from observer.capture_backend import CaptureRecord, TcpdumpBackend, TsharkBackend
from observer.correlator import ExchangeCorrelator

FIXTURES = Path(__file__).parent / "fixtures"


def tshark_records() -> list[CaptureRecord]:
    # Real TShark 4.6 output captured on the Windows loopback adapter (1 health + 2 POSTs).
    lines = (FIXTURES / "tshark_fields_sample.tsv").read_text(encoding="utf-8").splitlines()
    return [r for r in (TsharkBackend.parse_line(line) for line in lines) if r is not None]


# ---- TShark parsing ----------------------------------------------------

def test_tshark_parse_real_output() -> None:
    records = tshark_records()
    assert [r.kind for r in records] == ["request", "response"] * 3
    post = records[2]
    assert post.method == "POST" and post.uri == "/api/test"
    assert post.src_ip == "127.0.0.1" and post.dst_port == 8765
    assert post.headers["x-sender"] == "probe"
    assert post.body["sequence"] == "1"  # JSON body readable because TShark reassembled it
    assert post.message_len == 428 and post.frame_len == 199
    resp = records[3]
    assert resp.status_code == 200 and resp.request_id == post.request_id
    assert resp.http_time_ms is not None and resp.http_time_ms > 0


def test_keepalive_puts_all_requests_on_one_tcp_stream() -> None:
    # This is why tcp.stream must not be the correlation ID.
    records = tshark_records()
    assert {r.tcp_stream for r in records} == {0}
    assert len({r.request_id for r in records}) == 3


def test_tshark_ignores_garbage_lines() -> None:
    assert TsharkBackend.parse_line("") is None
    assert TsharkBackend.parse_line("Capturing on 'eth0'") is None


# ---- tcpdump parsing (synthetic sample in `tcpdump -nn -tt -A` format) ---

TCPDUMP_SAMPLE = """\
1790222457.316154 IP 192.168.56.1.54000 > 192.168.56.101.8000: Flags [P.], seq 1:200, ack 1, win 8212, length 199
E.....@.......8...8e.....P.....POST /api/test HTTP/1.1
Host: 192.168.56.101:8000
X-Request-ID: {rid}
X-Sender: windows
Content-Length: 155

1790222457.316300 IP 192.168.56.101.8000 > 192.168.56.1.54000: Flags [.], ack 200, win 501, length 0
E..(..@.@.........
1790222457.321075 IP 192.168.56.101.8000 > 192.168.56.1.54000: Flags [P.], seq 1:236, ack 355, win 501, length 235
E.....@.@.........HTTP/1.1 200 OK
date: Thu, 24 Sep 2026 04:00:57 GMT
x-request-id: {rid}
x-receiver: kali

"""


def test_tcpdump_parse_request_and_response() -> None:
    rid = new_request_id()
    backend = TcpdumpBackend("tcpdump", "eth0", "tcp port 8000", logging.getLogger("t"))
    records = list(backend.parse_stream(TCPDUMP_SAMPLE.format(rid=rid).splitlines(keepends=True)))
    assert [r.kind for r in records] == ["request", "response"]
    req, resp = records
    assert (req.method, req.uri, req.src_ip, req.src_port, req.dst_port) == ("POST", "/api/test", "192.168.56.1", 54000, 8000)
    assert req.request_id == rid and req.sender == "windows"
    assert resp.status_code == 200 and resp.request_id == rid and resp.receiver == "kali"


# ---- correlation -------------------------------------------------------

def test_correlator_pairs_capture_by_request_id() -> None:
    corr = ExchangeCorrelator("probe", merge_window=0)
    for record in tshark_records():
        corr.add_capture_record(record)
    events = corr.flush()
    assert len(events) == 3
    posts = [e for e in events if e["endpoint"] == "/api/test"]
    assert [e["payload"]["sequence"] for e in posts] == [1, 2]
    for event in events:
        assert event["status_code"] == 200
        assert event["wire_latency_ms"] > 0
        assert event["evidence"] == ["capture"]
        assert event["tcp_stream"] == 0


def test_correlator_merges_all_sources_into_one_event() -> None:
    rid = new_request_id()
    corr = ExchangeCorrelator("windows", merge_window=0)
    corr.add_client_record({
        "record_type": "client_exchange", "request_id": rid, "sent_at": "2026-09-24T04:00:00.000Z",
        "sender": "windows", "receiver": "kali", "method": "POST", "endpoint": "/api/test",
        "source_ip": "192.168.56.1", "source_port": 50000, "destination_ip": "192.168.56.101",
        "destination_port": 8000, "status_code": 200, "client_rtt_ms": 18.4, "server_processing_ms": 2.1,
        "payload": {"message": "hi", "sender": "windows", "sequence": 1},
    })
    corr.add_capture_record(CaptureRecord(kind="request", timestamp=100.0, backend="tshark", method="POST",
                                          uri="/api/test", tcp_stream=7, message_len=400,
                                          headers={"x-request-id": rid}))
    corr.add_capture_record(CaptureRecord(kind="response", timestamp=100.017, backend="tshark", status_code=200,
                                          tcp_stream=7, message_len=380, headers={"x-request-id": rid}))
    [event] = corr.flush()
    assert event["direction"] == "windows_to_kali"
    assert event["vantage"] == "client_side"
    assert event["evidence"] == ["capture", "client_log"]
    assert event["latency_ms"] == 18.4 and event["latency_source"] == "client_rtt"
    assert event["server_processing_ms"] == 2.1
    assert abs(event["wire_latency_ms"] - 17.0) < 0.01
    assert event["tcp_stream"] == 7 and event["request_bytes"] == 400
    assert event["timestamp"] == "2026-09-24T04:00:00.000Z"


def test_correlator_server_side_view() -> None:
    rid = new_request_id()
    corr = ExchangeCorrelator("windows", merge_window=0)
    corr.add_server_record({
        "record_type": "server_exchange", "request_id": rid, "received_at": "2026-09-24T04:00:00.000Z",
        "sender": "kali", "receiver": "windows", "method": "POST", "endpoint": "/api/test",
        "status_code": 200, "server_processing_ms": 3.2, "payload": {"sender": "kali", "sequence": 2},
    })
    [event] = corr.flush()
    assert event["direction"] == "kali_to_windows"
    assert event["vantage"] == "server_side"
    assert event["latency_ms"] is None  # no round-trip view on the server side without capture
    assert event["server_processing_ms"] == 3.2


def test_correlator_handles_interleaved_requests() -> None:
    a, b = new_request_id(), new_request_id()
    corr = ExchangeCorrelator("kali", merge_window=0)
    # Two concurrent requests on the same TCP stream, responses in reverse order.
    corr.add_capture_record(CaptureRecord(kind="request", timestamp=1.0, backend="t", method="POST", uri="/a", tcp_stream=1, headers={"x-request-id": a}))
    corr.add_capture_record(CaptureRecord(kind="request", timestamp=1.1, backend="t", method="POST", uri="/b", tcp_stream=1, headers={"x-request-id": b}))
    corr.add_capture_record(CaptureRecord(kind="response", timestamp=1.3, backend="t", status_code=201, tcp_stream=1, headers={"x-request-id": b}))
    corr.add_capture_record(CaptureRecord(kind="response", timestamp=1.5, backend="t", status_code=200, tcp_stream=1, headers={"x-request-id": a}))
    events = {e["request_id"]: e for e in corr.flush()}
    assert events[a]["endpoint"] == "/a" and events[a]["status_code"] == 200
    assert abs(events[a]["wire_latency_ms"] - 500) < 0.01
    assert events[b]["endpoint"] == "/b" and events[b]["status_code"] == 201
    assert abs(events[b]["wire_latency_ms"] - 200) < 0.01


def test_correlator_rekeys_request_without_id() -> None:
    rid = new_request_id()
    corr = ExchangeCorrelator("kali", merge_window=0)
    corr.add_capture_record(CaptureRecord(kind="request", timestamp=1.0, backend="t", frame_number=10, method="GET", uri="/health"))
    corr.add_capture_record(CaptureRecord(kind="response", timestamp=1.01, backend="t", request_in=10, status_code=200, headers={"x-request-id": rid}))
    corr.add_server_record({"record_type": "server_exchange", "request_id": rid, "receiver": "kali", "status_code": 200})
    [event] = corr.flush()
    assert event["request_id"] == rid and event["endpoint"] == "/health"
    assert event["evidence"] == ["capture", "server_log"]


def test_correlator_waits_for_merge_window() -> None:
    corr = ExchangeCorrelator("kali", merge_window=60)
    corr.add_server_record({"record_type": "server_exchange", "request_id": new_request_id(), "status_code": 200})
    assert corr.flush() == []
    assert len(corr.flush(force=True)) == 1


def test_peer_names_fallback_for_direction() -> None:
    corr = ExchangeCorrelator("kali", {"192.168.56.1": "windows", "192.168.56.101": "kali"}, merge_window=0)
    corr.add_capture_record(CaptureRecord(kind="request", timestamp=1.0, backend="t", src_ip="192.168.56.1", dst_ip="192.168.56.101", method="GET", uri="/x", headers={"x-request-id": new_request_id()}))
    [event] = corr.flush(force=True)
    assert event["direction"] == "windows_to_kali"


# ---- JSONL tailer ------------------------------------------------------

def test_tailer_reads_only_complete_new_lines(tmp_path: Path) -> None:
    path = tmp_path / "x.jsonl"
    append_jsonl(path, {"n": 1})
    tailer = JsonlTailer(path)  # starts at end of file
    assert tailer.read_new() == []
    append_jsonl(path, {"n": 2})
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"n": 3')  # partial line still being written
    assert tailer.read_new() == [{"n": 2}]
    with path.open("a", encoding="utf-8") as fh:
        fh.write("}\n")
    assert tailer.read_new() == [{"n": 3}]
    assert JsonlTailer(path, from_start=True).read_new() == [{"n": 1}, {"n": 2}, {"n": 3}]
