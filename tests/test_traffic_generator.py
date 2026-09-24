from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from client.traffic_generator import (
    MAX_COUNT,
    SendResult,
    _summary,
    build_payload,
    check_health,
    parse_args,
    send_one,
)
from common.config import Settings
from models.schemas import is_valid_request_id


def test_build_payload_fields() -> None:
    payload = build_payload("windows", 4)
    assert payload.sender == "windows"
    assert payload.sequence == 4
    assert is_valid_request_id(payload.request_id)
    assert payload.sent_at.utcoffset().total_seconds() == 0
    assert build_payload("windows", 5).request_id != payload.request_id


def test_send_one_against_real_app(client: TestClient) -> None:
    payload = build_payload("windows", 1)
    result = send_one(client, "http://testserver", payload, retries=0, retry_backoff=0)
    assert result.ok
    assert result.request_id == payload.request_id
    assert result.receiver == "kali"
    assert result.client_rtt_ms is not None and result.server_processing_ms is not None
    # The client-measured duration contains the server processing time.
    assert result.client_rtt_ms >= result.server_processing_ms


def test_health_check_against_real_app(client: TestClient) -> None:
    assert check_health(client, "http://testserver", "windows")


def _mock_client(statuses: list[int]) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        status = statuses[min(len(seen) - 1, len(statuses) - 1)]
        return httpx.Response(status, json={"detail": "mock"})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_retries_on_server_error_with_same_request_id() -> None:
    http, seen = _mock_client([500, 503, 500])
    result = send_one(http, "http://x", build_payload("kali", 1), retries=2, retry_backoff=0)
    assert result.attempts == 3 and not result.ok and result.status_code == 500
    assert len({r.headers["X-Request-ID"] for r in seen}) == 1


def test_no_retry_on_client_error() -> None:
    http, seen = _mock_client([422])
    result = send_one(http, "http://x", build_payload("kali", 1), retries=3, retry_backoff=0)
    assert result.attempts == 1 and len(seen) == 1 and result.status_code == 422


def test_connection_error_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    result = send_one(http, "http://x", build_payload("kali", 1), retries=1, retry_backoff=0)
    assert result.attempts == 2
    assert result.status_code is None
    assert result.error and "connection failed" in result.error


def test_parse_args_defaults_are_safe(settings: Settings) -> None:
    args = parse_args(replace(settings, default_count=5, default_delay=5.0), ["--target", "http://10.0.0.1:8000"])
    assert args.count == 5 and args.delay == 5.0


@pytest.mark.parametrize("argv", [
    ["--count", "0"],
    ["--count", str(MAX_COUNT + 1)],
    ["--delay", "-1"],
    ["--timeout", "0"],
    ["--sender", "bad name"],
    ["--target", "10.0.0.1:8000"],  # missing scheme
])
def test_parse_args_rejects_unsafe_values(settings: Settings, argv: list[str]) -> None:
    base = ["--target", "http://10.0.0.1:8000"] if "--target" not in argv else []
    with pytest.raises(SystemExit):
        parse_args(settings, base + argv)


def test_parse_args_requires_target(settings: Settings) -> None:
    with pytest.raises(SystemExit):
        parse_args(replace(settings, target_host=""), [])


def test_summary_exit_code() -> None:
    ok = SendResult(sequence=1, request_id="a", status_code=200, client_rtt_ms=5, server_processing_ms=1)
    bad = SendResult(sequence=2, request_id="b", error="timeout")
    assert _summary([ok], planned=1) == 0
    assert _summary([ok, bad], planned=2) == 1
    assert _summary([ok], planned=2) == 1  # interrupted early
