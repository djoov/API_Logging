"""Pydantic schemas shared by server, client and observer."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

# Node names end up in direction labels such as "windows_to_kali".
NODE_NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{0,31}$"

# HTTP headers used to carry correlation data outside the JSON body. Headers
# arrive in the first TCP segment, so packet capture can read them even when
# the body is split across segments.
HEADER_REQUEST_ID = "X-Request-ID"
HEADER_SENDER = "X-Sender"
HEADER_RECEIVER = "X-Receiver"
HEADER_PROCESSING_MS = "X-Processing-Time-Ms"


def new_request_id() -> str:
    return str(uuid.uuid4())


def normalize_request_id(value: str) -> str:
    """Return the canonical lowercase UUID string, or raise ValueError."""
    try:
        return str(uuid.UUID(str(value).strip()))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"request_id must be a UUID, got {value!r}") from exc


def is_valid_request_id(value: str) -> bool:
    try:
        normalize_request_id(value)
        return True
    except ValueError:
        return False


class ApiTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=1024)
    sender: str = Field(pattern=NODE_NAME_PATTERN)
    request_id: str
    sequence: int = Field(ge=1)
    sent_at: AwareDatetime

    @field_validator("request_id")
    @classmethod
    def _check_request_id(cls, value: str) -> str:
        return normalize_request_id(value)


class ApiTestResponse(BaseModel):
    status: Literal["ok"]
    message: str
    receiver: str
    request_id: str
    sequence: int
    received_at: AwareDatetime
    processing_time_ms: float = Field(ge=0)


class HealthResponse(BaseModel):
    status: Literal["ok"]


class PayloadMetadata(BaseModel):
    message: str | None = None
    sender: str | None = None
    sequence: int | None = None


class ApiExchangeEvent(BaseModel):
    """One observed request/response pair, written to logs/api-events.jsonl.

    Latency fields are kept separate on purpose:
      client_rtt_ms        - measured by the client: send request -> full response received
      server_processing_ms - measured by the server: request received -> response ready
      wire_latency_ms      - measured by packet capture on *this* host: request packet -> response packet
    latency_ms is the best round-trip figure available and latency_source says which one it is.
    """

    event_type: Literal["api_exchange"] = "api_exchange"
    timestamp: str
    observer: str
    direction: str
    vantage: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    method: str | None = None
    endpoint: str | None = None
    status_code: int | None = None
    latency_ms: float | None = None
    latency_source: str | None = None
    client_rtt_ms: float | None = None
    server_processing_ms: float | None = None
    wire_latency_ms: float | None = None
    request_id: str | None = None
    tcp_stream: int | None = None
    request_bytes: int | None = None
    response_bytes: int | None = None
    evidence: list[str] = Field(default_factory=list)
    payload: PayloadMetadata = Field(default_factory=PayloadMetadata)
    error: str | None = None
    # Phase 2
    # TLS only: request start -> FIRST response record. wire_latency_ms is to the LAST record.
    wire_ttfb_ms: float | None = None
    transport: str | None = None  # "http" or "https"
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_sni: str | None = None  # empty when the client connects to an IP address
    # How wire evidence was tied to this exchange: "request_id" (plaintext header),
    # "4tuple_time" (TLS: same connection + close in time), or None (no capture / unmatched).
    capture_match: str | None = None

    def to_record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
