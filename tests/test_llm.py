"""Phase 6 tests: Ollama protocol parsing, HTTPS gateway + mock Ollama + LLM client end to end."""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest
import uvicorn

from client.llm_client import build_body, build_secure_envelope, send_prompt
from client.traffic_generator import build_verify
from common.config import Settings
from gateway.ollama_gateway import create_gateway_app
from llm.ollama_protocol import OllamaResponseAssembler, extract_prompt
from llm.openai_protocol import OPENAI_CHAT, OpenAIResponseAssembler
from llm.openai_protocol import extract_prompt as openai_extract_prompt
from models.schemas import new_request_id
from observer.correlator import ExchangeCorrelator
from security.payload_crypto import decrypt_payload, generate_key, key_id
from security.tls_certs import create_ca, create_server_cert
from tools.mock_ollama import create_app as create_mock_ollama

GATEWAY_KEY = generate_key()


# ---- protocol parsing --------------------------------------------------

def test_extract_prompt() -> None:
    assert extract_prompt("/api/generate", {"prompt": "halo"}) == "halo"
    chat = {"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u1"},
                         {"role": "assistant", "content": "a"}, {"role": "user", "content": "u2"}]}
    assert extract_prompt("/api/chat", chat) == "u2"
    assert extract_prompt("/api/chat", {"messages": []}) is None


def test_assembler_joins_stream_split_across_network_chunks() -> None:
    lines = [{"response": "Hal", "done": False}, {"response": "o dunia", "done": False},
             {"response": "", "done": True, "eval_count": 2, "eval_duration": 500_000_000,
              "load_duration": 1_500_000_000, "total_duration": 2_000_000_000}]
    raw = "".join(json.dumps(line) + "\n" for line in lines).encode()
    asm = OllamaResponseAssembler("/api/generate")
    for i in range(0, len(raw), 7):  # arbitrary split points, like TCP delivery
        asm.feed_bytes(raw[i:i + 7], at=float(i))
    asm.close(at=999.0)
    s = asm.summary()
    assert asm.text == "Halo dunia" and asm.chunks == 3
    assert s["response_tokens"] == 2 and s["tokens_per_s"] == 4.0
    assert s["ollama_load_ms"] == 1500.0 and s["ollama_total_ms"] == 2000.0
    # A piece of text only counts once its whole JSON line has arrived: that is the network
    # chunk containing the first newline, not the very first chunk.
    first_line_end = len(json.dumps(lines[0])) + 1
    assert asm.first_chunk_at == float((first_line_end - 1) // 7 * 7)


def test_assembler_chat_and_non_stream_and_error() -> None:
    chat = OllamaResponseAssembler("/api/chat")
    chat.feed_bytes(json.dumps({"message": {"role": "assistant", "content": "ok"}, "done": True}).encode(), 1.0)
    chat.close(2.0)  # non-streaming body has no trailing newline
    assert chat.text == "ok" and chat.summary()["done"]

    err = OllamaResponseAssembler("/api/generate")
    err.feed_bytes(b'{"error":"model \'x\' not found"}', 1.0)
    err.close(1.0)
    assert err.summary()["error"] == "model 'x' not found"


# ---- end to end: client --HTTPS--> gateway --HTTP--> mock Ollama ----------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(app: Any, port: int, **tls: str) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", **tls))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    return server, thread


@contextmanager
def _running_lab(settings: Settings, tmp_path: Path, app_key: bytes | None) -> Iterator[dict[str, Any]]:
    certs = tmp_path / "certs"
    create_ca(certs)
    create_server_cert(certs, certs, "gw", ["127.0.0.1"])
    ollama_port, gateway_port = _free_port(), _free_port()
    gw_settings = replace(settings, node_name="windows", ollama_url=f"http://127.0.0.1:{ollama_port}",
                          llm_timeout=30.0)
    ollama = _serve(create_mock_ollama(token_delay_ms=1, load_ms=0), ollama_port)
    gateway = _serve(create_gateway_app(gw_settings, app_key), gateway_port,
                     ssl_certfile=str(certs / "gw.pem"), ssl_keyfile=str(certs / "gw.key"))
    target = f"https://127.0.0.1:{gateway_port}"
    client = httpx.Client(verify=build_verify(target, certs / "ca.pem"), timeout=30)
    try:
        yield {"target": target, "client": client, "settings": gw_settings, "ollama_port": ollama_port,
               "certs": certs}
    finally:
        client.close()
        for server, thread in (gateway, ollama):
            server.should_exit = True
            thread.join(timeout=5)


@pytest.fixture
def lab(settings: Settings, tmp_path: Path) -> Iterator[dict[str, Any]]:
    """Gateway WITHOUT a payload key (plain Phase 6, and Test C for /secure)."""
    with _running_lab(settings, tmp_path, None) as running:
        yield running


@pytest.fixture
def secure_lab(settings: Settings, tmp_path: Path) -> Iterator[dict[str, Any]]:
    """Gateway holding the payload key: authorized decryption point (Test D)."""
    with _running_lab(settings, tmp_path, GATEWAY_KEY) as running:
        yield running


def _gateway_records(settings: Settings) -> list[dict[str, Any]]:
    path = settings.log_dir / "server-events.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("endpoint", ["/api/generate", "/api/chat"])
@pytest.mark.parametrize("stream", [True, False])
def test_prompt_and_answer_logged_on_both_sides(lab: dict[str, Any], endpoint: str, stream: bool) -> None:
    prompt = "Jelaskan TCP handshake"
    result = send_prompt(lab["client"], lab["target"], endpoint, "mock-llm", prompt, stream, "kali", 1)

    assert result.ok, result.error
    assert result.tls_version in ("TLSv1.2", "TLSv1.3") and result.receiver == "windows"
    assert "SIMULASI mock-ollama" in result.response and prompt in result.response
    assert result.summary["response_tokens"] and result.ttft_ms is not None
    assert result.ttft_ms <= result.total_ms

    [record] = _gateway_records(lab["settings"])
    assert record["record_type"] == "llm_gateway_exchange" and record["transport"] == "https"
    assert record["request_id"] == result.request_id and record["sender"] == "kali"
    assert record["llm"]["prompt"] == prompt
    assert record["llm"]["response"] == result.response  # the very same full answer on both hosts
    assert record["llm"]["stream"] is stream and record["status_code"] == 200


def test_unknown_model_error_reaches_both_sides(lab: dict[str, Any]) -> None:
    result = send_prompt(lab["client"], lab["target"], "/api/generate", "no-such-model", "hi", True, "kali", 1)
    assert result.status_code == 404 and "not found" in (result.error or "")
    [record] = _gateway_records(lab["settings"])
    assert record["status_code"] == 404 and "not found" in record["error"]


def test_gateway_reports_ollama_down(settings: Settings) -> None:
    from fastapi.testclient import TestClient

    down = replace(settings, ollama_url=f"http://127.0.0.1:{_free_port()}", llm_timeout=5.0)
    with TestClient(create_gateway_app(down)) as client:
        response = client.post("/api/generate", json={"model": "m", "prompt": "p"})
    assert response.status_code == 502 and "unreachable at" in response.json()["error"]
    [record] = _gateway_records(down)
    assert record["status_code"] == 502 and record["llm"]["prompt"] == "p"


def test_correlator_merges_llm_from_client_and_gateway() -> None:
    rid = "0bbb9655-7279-4e96-ab8f-08634cf19944"
    corr = ExchangeCorrelator("windows", merge_window=0)
    corr.add_client_record({"record_type": "llm_client_exchange", "request_id": rid, "sent_at": "2026-09-24T12:00:00.000Z",
                            "sender": "ubuntu", "receiver": "windows", "status_code": 200, "client_rtt_ms": 900.0,
                            "llm": {"prompt": "p", "response": "full answer", "client_ttft_ms": 120.0}})
    corr.add_server_record({"record_type": "llm_gateway_exchange", "request_id": rid, "received_at": "2026-09-24T12:00:00.010Z",
                            "sender": "ubuntu", "receiver": "windows", "status_code": 200,
                            "llm": {"prompt": "p", "response": "full answer", "gateway_ttft_ms": 100.0, "model": "m"}})
    [event] = corr.flush(force=True)
    assert event["llm"]["prompt"] == "p" and event["llm"]["response"] == "full answer"
    assert event["llm"]["client_ttft_ms"] == 120.0 and event["llm"]["gateway_ttft_ms"] == 100.0
    assert event["evidence"] == ["client_log", "server_log"]


# ---- Phase 3/4 on the Ollama gateway: /secure/api/generate|chat -----------

@pytest.mark.parametrize("endpoint", ["/api/generate", "/api/chat"])
@pytest.mark.parametrize("stream", [True, False])
def test_secure_prompt_authorized_gateway(secure_lab: dict[str, Any], endpoint: str, stream: bool) -> None:
    prompt = "Rahasia: jelaskan TLS"
    result = send_prompt(secure_lab["client"], secure_lab["target"], endpoint, "mock-llm", prompt, stream,
                         "kali", 1, app_key=GATEWAY_KEY)
    assert result.ok, result.error
    assert result.decryption_status == "authorized" and result.app_encryption == "fernet"
    assert prompt in result.response and result.summary["response_tokens"]
    assert result.encrypted_lines == (result.summary["chunks"] if stream else 1)

    [record] = _gateway_records(secure_lab["settings"])
    assert record["decryption_status"] == "authorized" and record["key_id"] == key_id(GATEWAY_KEY)
    assert record["llm"]["prompt"] == prompt and record["llm"]["response"] == result.response
    assert record["endpoint"] == endpoint and record["request_id"] == result.request_id
    assert record["http_path"] == "/secure" + endpoint and result.http_path == "/secure" + endpoint

    # Evidence of encryption/decryption on EACH host:
    assert record["reply_encrypted_lines"] == result.encrypted_lines > 0  # gateway sent it encrypted...
    assert record["reply_ciphertext_bytes"] > 0
    assert result.reply_decryption_status == "ok"  # ...and this client decrypted it
    assert record["payload"]["sequence"] == 1
    der = ssl.PEM_cert_to_DER_cert((secure_lab["certs"] / "gw.pem").read_text())
    assert result.server_cert_sha256 == hashlib.sha256(der).hexdigest()  # verified THIS certificate


def _raw_secure_post(lab: dict[str, Any], key: bytes, prompt: str = "isi rahasia", stream: bool = True) -> httpx.Response:
    envelope = build_secure_envelope(build_body("/api/generate", "mock-llm", prompt, stream), new_request_id(),
                                     "kali", 1, datetime.now(timezone.utc).isoformat(), key)
    return lab["client"].post(lab["target"] + "/secure/api/generate", json=envelope)


def test_secure_wire_never_carries_prompt_or_answer(secure_lab: dict[str, Any]) -> None:
    envelope = build_secure_envelope(build_body("/api/generate", "mock-llm", "isi rahasia", True), new_request_id(),
                                     "kali", 1, datetime.now(timezone.utc).isoformat(), GATEWAY_KEY)
    assert "isi rahasia" not in json.dumps(envelope) and "mock-llm" not in json.dumps(envelope)
    response = _raw_secure_post(secure_lab, GATEWAY_KEY)
    assert response.status_code == 200 and "SIMULASI" not in response.text and "rahasia" not in response.text
    first = json.loads(response.text.splitlines()[0])
    assert set(first) == {"enc", "key_id", "ciphertext"}
    assert "response" in decrypt_payload(first["ciphertext"], GATEWAY_KEY)


def test_gateway_without_key_refuses_and_never_calls_ollama(lab: dict[str, Any]) -> None:
    response = _raw_secure_post(lab, GATEWAY_KEY)
    assert response.status_code == 403
    assert response.headers["X-Decryption-Status"] == "not_authorized"
    [record] = _gateway_records(lab["settings"])
    assert record["decryption_status"] == "not_authorized" and record["llm"]["prompt"] is None
    assert "rahasia" not in json.dumps(record)


def test_wrong_key_is_rejected(secure_lab: dict[str, Any]) -> None:
    response = _raw_secure_post(secure_lab, generate_key())
    assert response.status_code == 400 and response.headers["X-Decryption-Status"] == "failed"
    [record] = _gateway_records(secure_lab["settings"])
    assert record["decryption_status"] == "failed" and record["llm"]["prompt"] is None


def test_plain_endpoints_unchanged_on_gateway_with_key(secure_lab: dict[str, Any]) -> None:
    result = send_prompt(secure_lab["client"], secure_lab["target"], "/api/generate", "mock-llm", "halo", True,
                         "kali", 1)
    assert result.ok and result.decryption_status is None
    [record] = _gateway_records(secure_lab["settings"])
    assert record.get("decryption_status") is None and record["llm"]["prompt"] == "halo"


def test_per_line_encryption_coarsens_token_sizes(secure_lab: dict[str, Any]) -> None:
    # Research check: plaintext NDJSON pieces differ by 1 byte per extra character (token-length
    # side channel). Fernet (AES-CBC, 16-byte blocks) rounds each encrypted piece up, so an observer
    # sees far fewer distinct sizes. It does NOT hide the number of pieces.
    response = _raw_secure_post(secure_lab, GATEWAY_KEY, prompt="ukur ukuran potongan jawaban", stream=True)
    lines = [line for line in response.text.splitlines() if line.strip()]
    plaintext_sizes = [len(json.dumps(decrypt_payload(json.loads(l)["ciphertext"], GATEWAY_KEY))) for l in lines]
    encrypted_sizes = [len(l) for l in lines]
    assert len(set(encrypted_sizes)) < len(set(plaintext_sizes))
    assert len(lines) == len(plaintext_sizes)  # piece count is still visible


# ---- regression: streamed answers and the causality check ------------------

def _load_fixture(name: str) -> list[dict[str, Any]]:
    path = Path(__file__).parent / "fixtures" / name
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _correlate_secure_stream(shift_completed_ms: float = 0.0) -> list[dict[str, Any]]:
    from datetime import timedelta

    from observer.capture_backend import CaptureRecord

    corr = ExchangeCorrelator("gateway-host", merge_window=0, server_port=8443, tls_idle=30)
    for rec in _load_fixture("secure_stream_gateway.jsonl"):
        if shift_completed_ms:
            done = datetime.fromisoformat(rec["completed_at"].replace("Z", "+00:00"))
            rec["completed_at"] = (done + timedelta(milliseconds=shift_completed_ms)).isoformat()
        corr.add_server_record(rec)
    for data in _load_fixture("secure_stream_capture.jsonl"):
        data.pop("request_id", None)
        corr.add_capture_record(CaptureRecord(**data))
    return [e for e in corr.flush(force=True) if e["request_id"]]


def test_streamed_secure_answers_match_capture() -> None:
    # Real capture of 3 streamed /secure answers (mock Ollama, loopback, 2026-09-28). The gateway now
    # logs completed_at = when the last piece was handed to the client, so causality holds.
    events = _correlate_secure_stream()
    assert len(events) == 3
    for event in events:
        assert "capture_tls" in event["evidence"] and event["capture_match"] == "4tuple_time"
        assert event["decryption_status"] == "authorized"
        assert abs(event["wire_latency_ms"] - event["server_processing_ms"]) < 5


def test_log_written_after_stream_close_breaks_matching() -> None:
    # Regression for the cross-host /secure run: the gateway used to log completed_at when the
    # upstream Ollama stream CLOSED, 22-28 ms after the last piece left. The observer then refused
    # every pairing (server "finished" after its last byte was on the wire).
    events = _correlate_secure_stream(shift_completed_ms=25)
    assert all("capture_tls" not in e["evidence"] for e in events)


def test_correlator_carries_encryption_evidence_from_both_logs() -> None:
    rid = new_request_id()
    corr = ExchangeCorrelator("windows", merge_window=0)
    corr.add_client_record({"record_type": "llm_client_exchange", "request_id": rid, "sent_at": "2026-09-28T12:00:00.000Z",
                            "status_code": 200, "app_encryption": "fernet", "decryption_status": "authorized",
                            "encrypted_lines": 26, "reply_decryption_status": "ok", "server_cert_sha256": "ab" * 32})
    corr.add_server_record({"record_type": "llm_gateway_exchange", "request_id": rid, "received_at": "2026-09-28T12:00:00.010Z",
                            "status_code": 200, "app_encryption": "fernet", "decryption_status": "authorized",
                            "reply_encrypted_lines": 26, "reply_ciphertext_bytes": 7000})
    [event] = corr.flush(force=True)
    assert event["reply_encrypted_lines"] == event["encrypted_lines"] == 26
    assert event["reply_decryption_status"] == "ok" and event["reply_ciphertext_bytes"] == 7000
    assert event["server_cert_sha256"] == "ab" * 32


# ---- OpenAI-compatible API (LM Studio, Ollama /v1): /v1/chat/completions ----

def test_openai_assembler_sse_split_across_chunks() -> None:
    def event(obj: dict[str, Any]) -> str:
        return f"data: {json.dumps(obj)}\n\n"
    raw = (": keep-alive comment\n\n"
           + event({"model": "m", "choices": [{"delta": {"role": "assistant", "content": ""}, "finish_reason": None}]})
           + event({"model": "m", "choices": [{"delta": {"content": "Hal"}, "finish_reason": None}]})
           + event({"model": "m", "choices": [{"delta": {"content": "o"}, "finish_reason": "stop"}]})
           + event({"model": "m", "choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 5}})
           + "data: [DONE]\n\n").encode()
    asm = OpenAIResponseAssembler()
    for i in range(0, len(raw), 9):
        asm.feed_bytes(raw[i:i + 9], at=float(i))
    asm.close(at=999.0)
    s = asm.summary()
    assert asm.text == "Halo" and asm.done and asm.error is None
    assert s["api_style"] == "openai" and s["model"] == "m" and s["done_reason"] == "stop"
    assert s["prompt_tokens"] == 3 and s["response_tokens"] == 5
    assert s["ollama_load_ms"] is None  # the OpenAI API reports no model-side timings
    assert s["tokens_per_s"] == round(4 / (asm.last_chunk_at - asm.first_chunk_at), 2)


def test_openai_assembler_non_stream_and_error() -> None:
    asm = OpenAIResponseAssembler()
    asm.feed_bytes(json.dumps({"model": "m", "usage": {"completion_tokens": 2}, "choices": [
        {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}).encode(), 1.0)
    asm.close(2.0)
    assert asm.text == "ok" and asm.summary()["done"] and asm.summary()["tokens_per_s"] is None

    # LM Studio pretty-prints a non-streamed answer over many lines (found live, 2026-10-01).
    pretty = json.dumps({"model": "qwen/qwen3-vl-4b", "usage": {"completion_tokens": 3}, "choices": [
        {"message": {"role": "assistant", "content": "API adalah\nantarmuka."}, "finish_reason": "stop"}]}, indent=2)
    lm = OpenAIResponseAssembler()
    for i in range(0, len(pretty), 5):
        lm.feed_bytes(pretty[i:i + 5].encode(), float(i))
    lm.close(999.0)
    assert lm.error is None and lm.text == "API adalah\nantarmuka." and lm.summary()["response_tokens"] == 3

    err = OpenAIResponseAssembler()
    err.feed_bytes(b'{"error": {"message": "model \'x\' not found", "type": "invalid_request_error"}}', 1.0)
    err.close(1.0)
    assert err.summary()["error"] == "model 'x' not found"
    assert openai_extract_prompt({"messages": [{"role": "user", "content": [
        {"type": "text", "text": "apa ini?"}, {"type": "image_url", "image_url": {"url": "data:..."}}]}]}) == "apa ini?"


@pytest.mark.parametrize("stream", [True, False])
def test_openai_prompt_and_answer_logged_on_both_sides(lab: dict[str, Any], stream: bool) -> None:
    prompt = "Jelaskan TLS handshake"
    result = send_prompt(lab["client"], lab["target"], OPENAI_CHAT, "mock-llm", prompt, stream, "kali", 1)
    assert result.ok, result.error
    assert "SIMULASI mock-ollama" in result.response and prompt in result.response
    assert result.summary["api_style"] == "openai" and result.summary["response_tokens"]  # usage, also when streaming
    assert result.summary["done"] and result.ttft_ms is not None

    [record] = _gateway_records(lab["settings"])
    assert record["endpoint"] == record["http_path"] == OPENAI_CHAT
    assert record["llm"]["prompt"] == prompt and record["llm"]["response"] == result.response
    assert record["llm"]["stream"] is stream and record["llm"]["api_style"] == "openai"
    assert record["llm"]["response_tokens"] == result.summary["response_tokens"]


def test_openai_stream_defaults_to_off(lab: dict[str, Any]) -> None:
    # The OpenAI API does not stream unless asked; the gateway must log that correctly.
    response = lab["client"].post(lab["target"] + OPENAI_CHAT,
                                  json={"model": "mock-llm", "messages": [{"role": "user", "content": "hai"}]})
    assert response.status_code == 200 and response.json()["choices"][0]["message"]["content"]
    [record] = _gateway_records(lab["settings"])
    assert record["llm"]["stream"] is False and record["llm"]["prompt"] == "hai"


def test_openai_models_pass_through(lab: dict[str, Any]) -> None:
    response = lab["client"].get(lab["target"] + "/v1/models")
    assert response.status_code == 200 and response.json()["data"][0]["id"] == "mock-llm"


@pytest.mark.parametrize("stream", [True, False])
def test_openai_secure_prompt_authorized_gateway(secure_lab: dict[str, Any], stream: bool) -> None:
    prompt = "Rahasia lewat API OpenAI"
    result = send_prompt(secure_lab["client"], secure_lab["target"], OPENAI_CHAT, "mock-llm", prompt, stream,
                         "kali", 1, app_key=GATEWAY_KEY)
    assert result.ok, result.error
    assert result.decryption_status == "authorized" and result.reply_decryption_status == "ok"
    assert prompt in result.response and result.summary["done"] and result.summary["response_tokens"]

    [record] = _gateway_records(secure_lab["settings"])
    assert record["http_path"] == "/secure" + OPENAI_CHAT and record["endpoint"] == OPENAI_CHAT
    assert record["llm"]["prompt"] == prompt and record["llm"]["response"] == result.response
    assert record["reply_encrypted_lines"] == result.encrypted_lines > (2 if stream else 0)


def test_openai_secure_wire_has_no_sse_plaintext(secure_lab: dict[str, Any]) -> None:
    body = build_body(OPENAI_CHAT, "mock-llm", "isi rahasia", True)
    envelope = build_secure_envelope(body, new_request_id(), "kali", 1, datetime.now(timezone.utc).isoformat(),
                                     GATEWAY_KEY)
    response = secure_lab["client"].post(secure_lab["target"] + "/secure" + OPENAI_CHAT, json=envelope)
    assert response.status_code == 200 and response.headers["content-type"].startswith("application/x-ndjson")
    assert "data:" not in response.text and "SIMULASI" not in response.text and "rahasia" not in response.text
    opened = [decrypt_payload(json.loads(line)["ciphertext"], GATEWAY_KEY) for line in response.text.splitlines()]
    assert opened[-1] == "[DONE]" and opened[-2]["usage"]["completion_tokens"] > 0
