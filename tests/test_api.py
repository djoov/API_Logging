from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from common.config import Settings
from models.schemas import (
    ApiTestRequest,
    ApiTestResponse,
    is_valid_request_id,
    new_request_id,
    normalize_request_id,
)
from server.api_server import create_app


def valid_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "message": "hello from windows",
        "sender": "windows",
        "request_id": new_request_id(),
        "sequence": 1,
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    body.update(overrides)
    return body


def read_server_events(settings: Settings) -> list[dict[str, object]]:
    path = settings.log_dir / "server-events.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ---- /health -----------------------------------------------------------

def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---- /api/test ---------------------------------------------------------

def test_api_test_response_structure(client: TestClient) -> None:
    body = valid_body(sequence=3)
    response = client.post("/api/test", json=body)

    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"status", "message", "receiver", "request_id", "sequence",
                         "received_at", "processing_time_ms"}
    assert data["status"] == "ok"
    assert data["message"] == "received"
    assert data["receiver"] == "kali"
    assert data["request_id"] == body["request_id"]
    assert data["sequence"] == 3
    ApiTestResponse.model_validate(data)  # response matches the published schema


def test_api_test_echoes_correlation_headers(client: TestClient) -> None:
    body = valid_body()
    response = client.post("/api/test", json=body)
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert response.headers["X-Receiver"] == "kali"
    assert float(response.headers["X-Processing-Time-Ms"]) >= 0


def test_processing_time_is_measured(client: TestClient) -> None:
    data = client.post("/api/test", json=valid_body()).json()
    assert isinstance(data["processing_time_ms"], float)
    assert 0 <= data["processing_time_ms"] < 1000


def test_processing_time_includes_server_work(settings: Settings) -> None:
    slow = TestClient(create_app(replace(settings, simulated_work_ms=50)))
    data = slow.post("/api/test", json=valid_body()).json()
    assert data["processing_time_ms"] >= 50


def test_received_at_is_utc(client: TestClient) -> None:
    data = client.post("/api/test", json=valid_body()).json()
    received = datetime.fromisoformat(data["received_at"].replace("Z", "+00:00"))
    assert received.utcoffset() is not None and received.utcoffset().total_seconds() == 0


# ---- schema validation -------------------------------------------------

@pytest.mark.parametrize("overrides", [
    {"request_id": "not-a-uuid"},
    {"request_id": ""},
    {"sequence": 0},
    {"sequence": "abc"},
    {"message": ""},
    {"sender": "Windows Laptop"},
    {"sender": "a_b"},  # "_" is reserved for direction labels such as windows_to_kali
    {"sent_at": "2026-09-24T10:00:00"},  # timezone required
    {"unexpected": "field"},
])
def test_invalid_payload_rejected(client: TestClient, overrides: dict[str, object]) -> None:
    assert client.post("/api/test", json=valid_body(**overrides)).status_code == 422


@pytest.mark.parametrize("missing", ["message", "sender", "request_id", "sequence", "sent_at"])
def test_missing_field_rejected(client: TestClient, missing: str) -> None:
    body = valid_body()
    del body[missing]
    assert client.post("/api/test", json=body).status_code == 422


def test_non_json_body_rejected(client: TestClient) -> None:
    response = client.post("/api/test", content=b"hello", headers={"Content-Type": "text/plain"})
    assert response.status_code == 422


# ---- request_id --------------------------------------------------------

def test_new_request_id_is_unique_uuid() -> None:
    ids = {new_request_id() for _ in range(1000)}
    assert len(ids) == 1000
    assert all(uuid.UUID(i).version == 4 for i in ids)


def test_request_id_validation() -> None:
    rid = new_request_id()
    assert is_valid_request_id(rid)
    assert not is_valid_request_id("abc123")
    assert normalize_request_id(rid.upper()) == rid


def test_schema_normalizes_request_id() -> None:
    rid = new_request_id()
    model = ApiTestRequest.model_validate(valid_body(request_id=rid.upper()))
    assert model.request_id == rid


def test_schema_rejects_invalid_request_id() -> None:
    with pytest.raises(ValidationError):
        ApiTestRequest.model_validate(valid_body(request_id="123"))


# ---- application logging -----------------------------------------------

def test_server_writes_exchange_record(client: TestClient, settings: Settings) -> None:
    body = valid_body(sequence=7)
    client.post("/api/test", json=body)
    [record] = read_server_events(settings)

    assert record["record_type"] == "server_exchange"
    assert record["request_id"] == body["request_id"]
    assert record["method"] == "POST"
    assert record["endpoint"] == "/api/test"
    assert record["status_code"] == 200
    assert record["sender"] == "windows"
    assert record["receiver"] == "kali"
    assert record["source_ip"]  # TestClient reports "testclient"
    assert record["payload"]["sequence"] == 7
    assert record["server_processing_ms"] >= 0


def test_rejected_request_is_logged_with_header_id(client: TestClient, settings: Settings) -> None:
    rid = new_request_id()
    client.post("/api/test", json=valid_body(sequence=0), headers={"X-Request-ID": rid})
    [record] = read_server_events(settings)
    assert record["status_code"] == 422
    assert record["request_id"] == rid


def test_server_assigns_request_id_when_missing(client: TestClient, settings: Settings) -> None:
    response = client.get("/health")
    assert is_valid_request_id(response.headers["X-Request-ID"])
    [record] = read_server_events(settings)
    assert record["request_id"] == response.headers["X-Request-ID"]
