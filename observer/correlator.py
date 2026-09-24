"""Merges evidence about the same API exchange into one api_exchange event.

Evidence sources on one host:
  client_log  - logs/client-events.jsonl (this host sent the request)
  server_log  - logs/server-events.jsonl (this host received the request)
  capture     - TShark/tcpdump HTTP records seen on the wire

The correlation key is the application-level request_id. TCP stream and frame numbers are only
used as a fallback for traffic that carries no request_id, and are kept as metadata.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from common.logging_utils import to_iso
from models.schemas import ApiExchangeEvent, PayloadMetadata
from observer.capture_backend import CaptureRecord


@dataclass
class _Pending:
    fields: dict[str, Any] = field(default_factory=dict)
    evidence: set[str] = field(default_factory=set)
    request_time: float | None = None  # capture timestamp of the request (epoch seconds)
    response_time: float | None = None
    last_update: float = field(default_factory=time.monotonic)

    def merge(self, updates: dict[str, Any]) -> None:
        # First source to provide a value wins; later sources only fill gaps.
        for key, value in updates.items():
            if value is not None and self.fields.get(key) is None:
                self.fields[key] = value
        self.last_update = time.monotonic()


class ExchangeCorrelator:
    def __init__(self, node_name: str, peer_names: dict[str, str] | None = None,
                 merge_window: float = 2.0, incomplete_timeout: float = 30.0) -> None:
        self.node_name = node_name
        self.peer_names = peer_names or {}
        self.merge_window = merge_window
        self.incomplete_timeout = incomplete_timeout
        self._pending: dict[str, _Pending] = {}
        self._frame_to_key: dict[int, str] = {}  # capture request frame -> key (fallback pairing)

    # ---- evidence input -------------------------------------------------

    def add_client_record(self, rec: dict[str, Any]) -> None:
        if rec.get("record_type") != "client_exchange" or not rec.get("request_id"):
            return
        entry = self._entry(rec["request_id"])
        entry.evidence.add("client_log")
        entry.merge({
            "request_id": rec["request_id"],
            "timestamp": rec.get("sent_at"),
            "sender": rec.get("sender"),
            "receiver": rec.get("receiver"),
            "source_ip": rec.get("source_ip"),
            "source_port": rec.get("source_port"),
            "destination_ip": rec.get("destination_ip"),
            "destination_port": rec.get("destination_port"),
            "method": rec.get("method"),
            "endpoint": rec.get("endpoint"),
            "status_code": rec.get("status_code"),
            "client_rtt_ms": rec.get("client_rtt_ms"),
            "server_processing_ms": rec.get("server_processing_ms"),
            "error": rec.get("error"),
            "target": rec.get("target"),
        })
        self._merge_payload(entry, rec.get("payload"))
        if rec.get("status_code") is None:
            entry.fields["failed"] = True  # request never got a response; flush without waiting

    def add_server_record(self, rec: dict[str, Any]) -> None:
        if rec.get("record_type") != "server_exchange" or not rec.get("request_id"):
            return
        entry = self._entry(rec["request_id"])
        entry.evidence.add("server_log")
        entry.merge({
            "request_id": rec["request_id"],
            "timestamp": rec.get("received_at"),
            "sender": rec.get("sender"),
            "receiver": rec.get("receiver"),
            "source_ip": rec.get("source_ip"),
            "source_port": rec.get("source_port"),
            "destination_ip": rec.get("destination_ip"),
            "destination_port": rec.get("destination_port"),
            "method": rec.get("method"),
            "endpoint": rec.get("endpoint"),
            "status_code": rec.get("status_code"),
            "server_processing_ms": rec.get("server_processing_ms"),
        })
        self._merge_payload(entry, rec.get("payload"))

    def add_capture_record(self, rec: CaptureRecord) -> None:
        if rec.kind == "request":
            key = rec.request_id or f"capture-frame-{rec.frame_number}-{rec.timestamp}"
            if rec.frame_number is not None:
                self._frame_to_key[rec.frame_number] = key
            entry = self._entry(key)
            entry.evidence.add("capture")
            entry.request_time = entry.request_time or rec.timestamp
            entry.merge({
                "request_id": rec.request_id,
                "sender": rec.sender,
                "source_ip": rec.src_ip,
                "source_port": rec.src_port,
                "destination_ip": rec.dst_ip,
                "destination_port": rec.dst_port,
                "method": rec.method,
                "endpoint": rec.uri,
                "tcp_stream": rec.tcp_stream,
                "request_bytes": rec.message_len,
            })
            if rec.body:
                sequence = rec.body.get("sequence")
                self._merge_payload(entry, {
                    "message": rec.body.get("message"),
                    "sender": rec.body.get("sender"),
                    "sequence": int(sequence) if sequence and sequence.isdigit() else None,
                })
        else:
            frame_key = self._frame_to_key.get(rec.request_in) if rec.request_in is not None else None
            if frame_key and rec.request_id and frame_key != rec.request_id:
                # Request had no X-Request-ID; the server assigned one in the response.
                self._rekey(frame_key, rec.request_id)
            key = rec.request_id or frame_key
            if key is None:
                return  # a response we cannot pair with anything
            entry = self._entry(key)
            entry.evidence.add("capture")
            entry.response_time = rec.timestamp
            wire_ms = rec.http_time_ms
            if wire_ms is None and entry.request_time is not None:
                wire_ms = (rec.timestamp - entry.request_time) * 1000
            entry.merge({
                "request_id": rec.request_id,
                "receiver": rec.receiver,
                "endpoint": rec.uri,
                "status_code": rec.status_code,
                "wire_latency_ms": None if wire_ms is None else round(wire_ms, 3),
                "response_bytes": rec.message_len,
                "tcp_stream": rec.tcp_stream,
            })

    # ---- output ---------------------------------------------------------

    def flush(self, force: bool = False) -> list[dict[str, Any]]:
        """Return finished events. An entry is finished when it has a status code (or failed)
        and has not received new evidence for merge_window seconds."""
        now = time.monotonic()
        done: list[dict[str, Any]] = []
        for key in list(self._pending):
            entry = self._pending[key]
            complete = entry.fields.get("status_code") is not None or entry.fields.get("failed")
            limit = self.merge_window if complete else self.incomplete_timeout
            if force or now - entry.last_update >= limit:
                done.append(self._build_event(entry))
                del self._pending[key]
        if len(self._frame_to_key) > 10_000:
            self._frame_to_key.clear()
        return done

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    # ---- helpers --------------------------------------------------------

    def _entry(self, key: str) -> _Pending:
        return self._pending.setdefault(key, _Pending())

    def _rekey(self, old: str, new: str) -> None:
        entry = self._pending.pop(old, None)
        if entry is None:
            return
        entry.fields["request_id"] = new
        target = self._pending.get(new)
        if target is None:
            self._pending[new] = entry
            return
        target.merge(entry.fields)
        target.evidence |= entry.evidence
        target.request_time = target.request_time or entry.request_time

    @staticmethod
    def _merge_payload(entry: _Pending, payload: dict[str, Any] | None) -> None:
        if not payload:
            return
        current = entry.fields.setdefault("payload", {})
        for name in ("message", "sender", "sequence"):
            if current.get(name) is None and payload.get(name) is not None:
                current[name] = payload[name]

    def _name_for_ip(self, ip: str | None) -> str | None:
        return self.peer_names.get(ip) if ip else None

    def _build_event(self, entry: _Pending) -> dict[str, Any]:
        f = entry.fields
        sender = f.get("sender") or self._name_for_ip(f.get("source_ip")) or "unknown"
        receiver = f.get("receiver") or self._name_for_ip(f.get("destination_ip")) or "unknown"

        if sender == self.node_name and receiver == self.node_name:
            vantage = "local"
        elif sender == self.node_name:
            vantage = "client_side"
        elif receiver == self.node_name:
            vantage = "server_side"
        else:
            vantage = "unknown"

        # Prefer the client's round trip; on the server side only the wire view exists, and
        # there it approximates server turnaround rather than a network round trip.
        if f.get("client_rtt_ms") is not None:
            latency, latency_source = f["client_rtt_ms"], "client_rtt"
        elif f.get("wire_latency_ms") is not None:
            latency = f["wire_latency_ms"]
            latency_source = "wire_server_side" if vantage == "server_side" else "wire"
        else:
            latency, latency_source = None, None

        timestamp = f.get("timestamp")
        if entry.request_time is not None and (timestamp is None or "client_log" not in entry.evidence):
            timestamp = to_iso(datetime.fromtimestamp(entry.request_time, tz=timezone.utc))

        event = ApiExchangeEvent(
            timestamp=timestamp or to_iso(datetime.now(timezone.utc)),
            observer=self.node_name,
            direction=f"{sender}_to_{receiver}",
            vantage=vantage,
            source_ip=f.get("source_ip"),
            source_port=f.get("source_port"),
            destination_ip=f.get("destination_ip"),
            destination_port=f.get("destination_port"),
            method=f.get("method"),
            endpoint=f.get("endpoint"),
            status_code=f.get("status_code"),
            latency_ms=latency,
            latency_source=latency_source,
            client_rtt_ms=f.get("client_rtt_ms"),
            server_processing_ms=f.get("server_processing_ms"),
            wire_latency_ms=f.get("wire_latency_ms"),
            request_id=f.get("request_id"),
            tcp_stream=f.get("tcp_stream"),
            request_bytes=f.get("request_bytes"),
            response_bytes=f.get("response_bytes"),
            evidence=sorted(entry.evidence),
            payload=PayloadMetadata(**f.get("payload", {})),
            error=f.get("error"),
        )
        return event.to_record()
