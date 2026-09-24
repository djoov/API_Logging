"""Merges evidence about the same API exchange into one api_exchange event.

Evidence sources on one host:
  client_log  - logs/client-events.jsonl (this host sent the request)
  server_log  - logs/server-events.jsonl (this host received the request)
  capture     - TShark/tcpdump HTTP records seen on the wire (plaintext, Phase 1)
  capture_tls - encrypted TLS exchanges rebuilt from record sizes/timing (Phase 2)

The correlation key is the application-level request_id. TCP stream and frame numbers are only
used as a fallback for traffic that carries no request_id, and are kept as metadata.

With HTTPS the request_id is encrypted, so a TLS exchange seen on the wire is matched to an
application log entry by connection 4-tuple (client IP:port -> server port) plus time proximity.
The event records how the capture evidence was matched in "capture_match".
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from common.logging_utils import to_iso
from models.schemas import ApiExchangeEvent, PayloadMetadata
from observer.capture_backend import CaptureRecord
from observer.tls_flows import TlsExchange, TlsExchangeTracker

# A TLS exchange and an app-log entry on the same connection must start within this many seconds.
TLS_MATCH_TOLERANCE_S = 5.0


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


@dataclass
class _Pending:
    fields: dict[str, Any] = field(default_factory=dict)
    evidence: set[str] = field(default_factory=set)
    request_time: float | None = None  # capture timestamp of the request (epoch seconds)
    response_time: float | None = None
    last_update: float = field(default_factory=time.monotonic)

    def merge(self, updates: dict[str, Any], touch: bool = True) -> None:
        # First source to provide a value wins; later sources only fill gaps.
        for key, value in updates.items():
            if value is not None and self.fields.get(key) is None:
                self.fields[key] = value
        if touch:
            self.last_update = time.monotonic()


class ExchangeCorrelator:
    def __init__(self, node_name: str, peer_names: dict[str, str] | None = None,
                 merge_window: float = 2.0, incomplete_timeout: float = 30.0,
                 server_port: int | None = None) -> None:
        self.node_name = node_name
        self.peer_names = peer_names or {}
        self.merge_window = merge_window
        self.incomplete_timeout = incomplete_timeout
        self._pending: dict[str, _Pending] = {}
        self._frame_to_key: dict[int, str] = {}  # capture request frame -> key (fallback pairing)
        self.tls = TlsExchangeTracker(server_port)
        self._tls_ready: list[tuple[TlsExchange, float]] = []  # finished exchanges awaiting a match

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
            "transport": rec.get("transport"),
            "tls_version": rec.get("tls_version"),
            "tls_cipher": rec.get("tls_cipher"),
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
            "transport": rec.get("transport"),
        })
        self._merge_payload(entry, rec.get("payload"))

    def add_capture_record(self, rec: CaptureRecord) -> None:
        if rec.kind.startswith("tls_"):
            now = time.monotonic()
            self._tls_ready += [(ex, now) for ex in self.tls.add(rec)]
            return
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
        self._tls_ready += [(ex, now) for ex in
                            self.tls.expire(self.merge_window, self.incomplete_timeout, force)]

        due = [key for key, entry in self._pending.items() if force or self._is_due(entry, now)]
        # 1) An app entry about to be emitted gets its TLS evidence first, even if the TLS
        #    exchange is still inside its own merge window.
        for key in due:
            entry = self._pending[key]
            candidates = [ex for ex, _ in self._tls_ready]
            candidates += [ex for ex in self.tls.in_progress() if ex.has_response]
            match = self._best_tls_match(entry, candidates)
            if match is not None:
                self._consume_tls(match)
                self._attach_tls(entry, match)
        # 2) Finished TLS exchanges look for any pending app entry; unmatched ones become
        #    capture-only events once they have waited one merge window for app logs.
        waiting: list[tuple[TlsExchange, float]] = []
        for ex, since in self._tls_ready:
            entry = self._best_entry_for(ex)
            # Mutual best only: on a keep-alive connection an earlier exchange with no app log
            # (e.g. the client's /health check) must not grab the log entry of the next request
            # while that request's own exchange is still in progress.
            if entry is not None and self._best_tls_match(entry, self._all_tls_candidates()) is ex:
                self._attach_tls(entry, ex)
            elif force or now - since >= self.merge_window:
                done.append(self._build_event(self._capture_only_entry(ex)))
            else:
                waiting.append((ex, since))
        self._tls_ready = waiting

        for key in due:
            done.append(self._build_event(self._pending.pop(key)))
        if len(self._frame_to_key) > 10_000:
            self._frame_to_key.clear()
        return done

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    # ---- helpers --------------------------------------------------------

    def _is_due(self, entry: _Pending, now: float) -> bool:
        complete = entry.fields.get("status_code") is not None or entry.fields.get("failed")
        limit = self.merge_window if complete else self.incomplete_timeout
        return now - entry.last_update >= limit

    @staticmethod
    def _tls_distance(entry: _Pending, ex: TlsExchange) -> float | None:
        """Seconds between entry and ex if they describe the same connection, else None."""
        f = entry.fields
        if "capture_tls" in entry.evidence or "capture" in entry.evidence:
            return None
        if f.get("source_ip") != ex.client_ip or f.get("source_port") != ex.client_port:
            return None
        if f.get("destination_port") not in (None, ex.server_port):
            return None
        started = _epoch(f.get("timestamp"))
        if started is None:
            return None
        distance = abs(started - ex.request_time)
        return distance if distance <= TLS_MATCH_TOLERANCE_S else None

    def _best_tls_match(self, entry: _Pending, candidates: list[TlsExchange]) -> TlsExchange | None:
        scored = [(d, ex) for ex in candidates if (d := self._tls_distance(entry, ex)) is not None]
        return min(scored, key=lambda item: item[0])[1] if scored else None

    def _best_entry_for(self, ex: TlsExchange) -> _Pending | None:
        scored = [(d, e) for e in self._pending.values() if (d := self._tls_distance(e, ex)) is not None]
        return min(scored, key=lambda item: item[0])[1] if scored else None

    def _all_tls_candidates(self) -> list[TlsExchange]:
        """Finished exchanges plus the ones still in progress on each connection."""
        return [ex for ex, _ in self._tls_ready] + self.tls.in_progress()

    def _consume_tls(self, ex: TlsExchange) -> None:
        self._tls_ready = [(e, s) for e, s in self._tls_ready if e is not ex]
        self.tls.take(ex)

    @staticmethod
    def _attach_tls(entry: _Pending, ex: TlsExchange) -> None:
        entry.evidence.add("capture_tls")
        entry.request_time = entry.request_time or ex.request_time
        entry.merge({
            "source_ip": ex.client_ip,
            "source_port": ex.client_port,
            "destination_ip": ex.server_ip,
            "destination_port": ex.server_port,
            "tcp_stream": ex.tcp_stream,
            "request_bytes": ex.request_bytes,
            "response_bytes": ex.response_bytes if ex.has_response else None,
            "wire_latency_ms": ex.wire_latency_ms,
            "wire_ttfb_ms": ex.wire_ttfb_ms,
            "transport": "https",
            "tls_version": ex.tls_version,
            "tls_cipher": ex.tls_cipher,
            "tls_sni": ex.tls_sni,
            "capture_match": "4tuple_time",
        }, touch=False)

    def _capture_only_entry(self, ex: TlsExchange) -> _Pending:
        """An encrypted exchange with no app log on this host: only wire metadata is known."""
        entry = _Pending()
        self._attach_tls(entry, ex)
        entry.fields["capture_match"] = None
        return entry

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

        if "capture" in entry.evidence:
            capture_match = "request_id"  # plaintext: X-Request-ID read from the wire
        else:
            capture_match = f.get("capture_match")
        transport = f.get("transport") or ("https" if "capture_tls" in entry.evidence
                                           else "http" if "capture" in entry.evidence else None)

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
            wire_ttfb_ms=f.get("wire_ttfb_ms"),
            request_id=f.get("request_id"),
            tcp_stream=f.get("tcp_stream"),
            request_bytes=f.get("request_bytes"),
            response_bytes=f.get("response_bytes"),
            evidence=sorted(entry.evidence),
            payload=PayloadMetadata(**f.get("payload", {})),
            error=f.get("error"),
            transport=transport,
            tls_version=f.get("tls_version"),
            tls_cipher=f.get("tls_cipher"),
            tls_sni=f.get("tls_sni"),
            capture_match=capture_match,
        )
        return event.to_record()
