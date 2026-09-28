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
HEADER_DECRYPTION = "X-Decryption-Status"  # Phase 3/4 on the streaming Ollama gateway


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


class SecureTestRequest(BaseModel):
    """Phase 3 envelope for POST /api/secure-test.

    Routing/correlation metadata stays in plaintext (so observers can still correlate and count);
    the business payload {"message": ...} is only inside the Fernet ciphertext.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str
    sender: str = Field(pattern=NODE_NAME_PATTERN)
    sequence: int = Field(ge=1)
    sent_at: AwareDatetime
    enc: Literal["fernet"]
    key_id: str = Field(min_length=1, max_length=32)
    ciphertext: str = Field(min_length=1, max_length=65536)

    @field_validator("request_id")
    @classmethod
    def _check_request_id(cls, value: str) -> str:
        return normalize_request_id(value)


class SecureTestResponse(BaseModel):
    status: Literal["ok"]
    message: str
    receiver: str
    request_id: str
    sequence: int
    received_at: AwareDatetime
    processing_time_ms: float = Field(ge=0)
    # "authorized": this server holds the key and decrypted the payload (Test D).
    # "not_authorized": no key here; payload accepted but never read (Test C).
    decryption_status: Literal["authorized", "not_authorized"]
    enc: Literal["fernet"] | None = None
    key_id: str | None = None
    ciphertext: str | None = None  # encrypted reply, only when the server could decrypt


class SecureLlmEnvelope(BaseModel):
    """Phase 3/4 + 6 envelope for POST /secure/api/generate|chat on the Ollama gateway.

    The WHOLE Ollama request body (model, prompt/messages, options) is inside the ciphertext;
    only routing/correlation metadata is clear.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str
    sender: str = Field(pattern=NODE_NAME_PATTERN)
    sequence: int = Field(ge=1)
    sent_at: AwareDatetime
    enc: Literal["fernet"]
    key_id: str = Field(min_length=1, max_length=32)
    ciphertext: str = Field(min_length=1, max_length=2_000_000)

    @field_validator("request_id")
    @classmethod
    def _check_request_id(cls, value: str) -> str:
        return normalize_request_id(value)


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
    http_path: str | None = None  # when it differs from endpoint (e.g. /secure/api/generate)
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
    # Phase 3/4: application-layer encryption of the payload and who could read it.
    app_encryption: str | None = None  # "fernet" when the payload was encrypted by the application
    key_id: str | None = None  # key fingerprint (never the key)
    ciphertext_bytes: int | None = None
    # "authorized" (key holder decrypted), "not_authorized" (no key, payload unread),
    # "failed" (wrong key / tampered), None (payload not encrypted)
    decryption_status: str | None = None
    # Phase 6 (Ollama): model, full prompt and answer, time to first token, token statistics.
    # Filled only from the app logs of the LLM client / gateway, never from encrypted capture.
    llm: dict[str, Any] | None = None

    def to_record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
