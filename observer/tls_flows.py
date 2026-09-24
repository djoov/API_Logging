"""PHASE 2: rebuild request/response exchanges from encrypted TLS records (no decryption).

HTTP/1.1 over one TLS connection is strictly sequential: the client sends a request, the
server answers, then the next request may follow. So, per TCP connection:
  client application-data record(s)  -> start (or continue) a request
  server application-data record(s)  -> the response to the open request
  next client record after a response -> the previous exchange is finished

TLS 1.3 session tickets: the server's first encrypted record after the handshake is a
NewSessionTicket, not a response, even when it arrives after the first request was sent.

What this cannot know: method, URI, status, headers, request_id - those are encrypted.
Only timing and encrypted sizes are available. Record sizes include TLS overhead
(about 17 bytes per record for TLS 1.3 AEAD), so they approximate, not equal, HTTP sizes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from observer.capture_backend import CaptureRecord

FlowKey = tuple[str, int, str, int]  # client_ip, client_port, server_ip, server_port

# Client records this small are alerts (e.g. close_notify is 19-24 bytes), not HTTP requests.
MIN_REQUEST_BYTES = 25


@dataclass
class TlsExchange:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    tcp_stream: int | None
    request_time: float  # capture epoch seconds
    request_bytes: int
    response_time: float | None = None
    response_bytes: int = 0
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_sni: str | None = None
    last_update: float = field(default_factory=time.monotonic)

    @property
    def has_response(self) -> bool:
        return self.response_time is not None

    @property
    def wire_latency_ms(self) -> float | None:
        if self.response_time is None:
            return None
        return round((self.response_time - self.request_time) * 1000, 3)


@dataclass
class _Flow:
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_sni: str | None = None
    current: TlsExchange | None = None
    # TLS 1.3 servers send NewSessionTicket(s) as encrypted records right after the handshake.
    # They can arrive before OR after the first request, so they are skipped by position,
    # not by timing. Assumes one ticket flight per connection (OpenSSL/Python ssl default).
    expect_ticket: bool = False


class TlsExchangeTracker:
    def __init__(self, server_port: int | None = None) -> None:
        # Ports known to be the server side; ClientHello destinations are learned automatically.
        self.server_ports: set[int] = {server_port} if server_port else set()
        self._flows: dict[FlowKey, _Flow] = {}
        self.ignored_server_records = 0  # e.g. TLS 1.3 session tickets, close_notify

    def _orient(self, rec: CaptureRecord) -> tuple[FlowKey, bool] | None:
        """(flow key, True if client->server) or None if the direction is unknown."""
        if None in (rec.src_ip, rec.dst_ip, rec.src_port, rec.dst_port):
            return None
        assert rec.src_ip and rec.dst_ip and rec.src_port and rec.dst_port
        if rec.dst_port in self.server_ports:
            return (rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port), True
        if rec.src_port in self.server_ports:
            return (rec.dst_ip, rec.dst_port, rec.src_ip, rec.src_port), False
        return None

    def add(self, rec: CaptureRecord) -> list[TlsExchange]:
        """Feed one TLS record. Returns exchanges that became finished because of it."""
        if rec.kind == "tls_client_hello" and rec.dst_port:
            self.server_ports.add(rec.dst_port)
        oriented = self._orient(rec)
        if oriented is None:
            return []
        key, from_client = oriented
        flow = self._flows.setdefault(key, _Flow())

        if rec.kind == "tls_client_hello":
            flow.tls_sni = rec.tls_sni
            return []
        if rec.kind == "tls_server_hello":
            flow.tls_version, flow.tls_cipher = rec.tls_version, rec.tls_cipher
            flow.expect_ticket = rec.tls_version == "TLSv1.3"
            return []
        if rec.kind != "tls_app_data":
            return []  # other handshake records and plaintext alerts

        size = rec.tls_bytes or 0
        current = flow.current
        if from_client:
            if current is not None and not current.has_response:
                current.request_bytes += size  # request split over several records
                current.last_update = time.monotonic()
                return []
            finished = [current] if current is not None else []
            flow.current = None
            if size >= MIN_REQUEST_BYTES:
                flow.current = TlsExchange(
                    client_ip=key[0], client_port=key[1], server_ip=key[2], server_port=key[3],
                    tcp_stream=rec.tcp_stream, request_time=rec.timestamp, request_bytes=size,
                    tls_version=flow.tls_version, tls_cipher=flow.tls_cipher, tls_sni=flow.tls_sni,
                )
            return finished

        if flow.expect_ticket:
            flow.expect_ticket = False
            self.ignored_server_records += 1
            return []
        if current is None:
            self.ignored_server_records += 1  # e.g. close_notify when the server closes an idle connection
            return []
        if current.response_time is None:
            current.response_time = rec.timestamp
        current.response_bytes += size
        current.last_update = time.monotonic()
        return []

    def in_progress(self) -> list[TlsExchange]:
        return [flow.current for flow in self._flows.values() if flow.current is not None]

    def take(self, exchange: TlsExchange) -> None:
        """Remove an exchange that the caller has consumed early."""
        for flow in self._flows.values():
            if flow.current is exchange:
                flow.current = None

    def expire(self, idle_seconds: float, incomplete_seconds: float, force: bool = False) -> list[TlsExchange]:
        """Finish exchanges idle for idle_seconds (with a response) or incomplete_seconds (without)."""
        now = time.monotonic()
        done: list[TlsExchange] = []
        for flow in self._flows.values():
            ex = flow.current
            if ex is None:
                continue
            limit = idle_seconds if ex.has_response else incomplete_seconds
            if force or now - ex.last_update >= limit:
                done.append(ex)
                flow.current = None
        return done
