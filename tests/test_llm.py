"""Phase 4 tests: Ollama protocol parsing, HTTPS gateway + mock Ollama + LLM client end to end."""
from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest
import uvicorn

from client.llm_client import send_prompt
from client.traffic_generator import build_verify
from common.config import Settings
from gateway.ollama_gateway import create_gateway_app
from llm.ollama_protocol import OllamaResponseAssembler, extract_prompt
from observer.correlator import ExchangeCorrelator
from security.tls_certs import create_ca, create_server_cert
from tools.mock_ollama import create_app as create_mock_ollama


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


@pytest.fixture
def lab(settings: Settings, tmp_path: Path) -> Iterator[dict[str, Any]]:
    certs = tmp_path / "certs"
    create_ca(certs)
    create_server_cert(certs, certs, "gw", ["127.0.0.1"])
    ollama_port, gateway_port = _free_port(), _free_port()
    gw_settings = replace(settings, node_name="windows", ollama_url=f"http://127.0.0.1:{ollama_port}",
                          llm_timeout=30.0)
    ollama = _serve(create_mock_ollama(token_delay_ms=1, load_ms=0), ollama_port)
    gateway = _serve(create_gateway_app(gw_settings), gateway_port,
                     ssl_certfile=str(certs / "gw.pem"), ssl_keyfile=str(certs / "gw.key"))
    target = f"https://127.0.0.1:{gateway_port}"
    client = httpx.Client(verify=build_verify(target, certs / "ca.pem"), timeout=30)
    yield {"target": target, "client": client, "settings": gw_settings, "ollama_port": ollama_port}
    client.close()
    for server, thread in (gateway, ollama):
        server.should_exit = True
        thread.join(timeout=5)


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
    assert response.status_code == 502 and "Ollama unreachable" in response.json()["error"]
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
