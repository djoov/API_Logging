"""Controlled traffic generator: sends a fixed number of requests with a delay between them.

Example (from the project root or from client/):
    python client/traffic_generator.py --target http://<KALI_IP>:8000 --sender windows --count 5 --delay 7
"""
from __future__ import annotations

import argparse
import re
import ssl
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # allow "python traffic_generator.py"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from common.config import ConfigError, Settings, load_settings
from common.jsonl import append_jsonl
from common.logging_utils import get_logger, to_iso, utc_now
from models.schemas import (
    HEADER_REQUEST_ID,
    HEADER_SENDER,
    NODE_NAME_PATTERN,
    ApiTestRequest,
    ApiTestResponse,
    new_request_id,
)

log = get_logger("client")

ENDPOINT = "/api/test"
MAX_COUNT = 1000  # safety cap: this tool is for controlled experiments, not load testing


@dataclass
class SendResult:
    sequence: int
    request_id: str
    status_code: int | None = None
    client_rtt_ms: float | None = None
    server_processing_ms: float | None = None
    receiver: str | None = None
    attempts: int = 0
    error: str | None = None
    local_addr: tuple[str, int] | None = None
    remote_addr: tuple[str, int] | None = None
    sent_at: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    tls_version: str | None = None  # e.g. "TLSv1.3"; None for plain HTTP
    tls_cipher: str | None = None

    @property
    def ok(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300


def build_payload(sender: str, sequence: int, message: str | None = None) -> ApiTestRequest:
    return ApiTestRequest(
        message=message or f"hello from {sender} #{sequence}",
        sender=sender,
        request_id=new_request_id(),
        sequence=sequence,
        sent_at=utc_now(),
    )


def _socket_addresses(response: httpx.Response) -> tuple[Any, Any]:
    """(local, remote) socket address of the connection used, if httpcore exposes it."""
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None, None
    try:
        return stream.get_extra_info("client_addr"), stream.get_extra_info("server_addr")
    except Exception:
        return None, None


def _tls_info(response: httpx.Response) -> tuple[str | None, str | None]:
    """(TLS version, cipher name) negotiated on the connection, or (None, None) for plain HTTP."""
    stream = response.extensions.get("network_stream")
    try:
        ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
    except Exception:
        ssl_object = None
    if ssl_object is None:
        return None, None
    cipher = ssl_object.cipher()
    return ssl_object.version(), cipher[0] if cipher else None


def build_verify(target: str, ca_file: Path | None) -> ssl.SSLContext | bool:
    """Certificate verification for https targets: trust the lab CA if given, else the system store.
    Verification is never disabled."""
    if not target.startswith("https://"):
        return True
    if ca_file is None:
        log.warning("WARNING https target without TLS_CA_FILE: using the system trust store, "
                    "which will reject lab certificates")
        return ssl.create_default_context()
    if not ca_file.is_file():
        raise FileNotFoundError(f"TLS_CA_FILE not found: {ca_file}")
    return ssl.create_default_context(cafile=str(ca_file))


def _explain_connect_error(exc: Exception) -> str:
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text:
        return (f"TLS certificate rejected: {text} -- is TLS_CA_FILE the lab ca.pem, and does the server "
                f"certificate list the target IP in its SubjectAltName? (scripts/make_certs.py show)")
    if "WRONG_VERSION_NUMBER" in text or "record layer failure" in text:
        return f"TLS handshake failed: {text} -- the server is probably plain HTTP; use http:// or enable TLS on it"
    return f"connection failed: {text}"


def send_one(
    client: httpx.Client,
    base_url: str,
    payload: ApiTestRequest,
    retries: int,
    retry_backoff: float,
) -> SendResult:
    """POST one payload. Retries on connection errors/timeouts and 5xx, never on 4xx.

    Every retry reuses the same request_id: it identifies the logical request, not the attempt.
    """
    url = base_url.rstrip("/") + ENDPOINT
    result = SendResult(
        sequence=payload.sequence,
        request_id=payload.request_id,
        sent_at=to_iso(payload.sent_at),
        payload={"message": payload.message, "sender": payload.sender, "sequence": payload.sequence},
    )
    headers = {HEADER_REQUEST_ID: payload.request_id, HEADER_SENDER: payload.sender}
    body = payload.model_dump(mode="json")

    for attempt in range(1, retries + 2):
        result.attempts = attempt
        log.info("SEND #%d request_id=%s target=%s attempt=%d", payload.sequence, payload.request_id, url, attempt)
        start = time.perf_counter()
        try:
            response = client.post(url, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            result.error = f"timeout: {type(exc).__name__}"
        except httpx.ConnectError as exc:
            result.error = _explain_connect_error(exc)
        except httpx.TransportError as exc:
            result.error = f"transport error: {type(exc).__name__}: {exc}"
        else:
            # Client request duration: request start -> full response body received.
            result.client_rtt_ms = (time.perf_counter() - start) * 1000
            result.status_code = response.status_code
            result.local_addr, result.remote_addr = _socket_addresses(response)
            result.tls_version, result.tls_cipher = _tls_info(response)
            if response.is_success:
                try:
                    parsed = ApiTestResponse.model_validate(response.json())
                    result.server_processing_ms = parsed.processing_time_ms
                    result.receiver = parsed.receiver
                    result.error = None
                except ValueError as exc:
                    result.error = f"invalid response body: {exc}"
                return result
            result.error = f"HTTP {response.status_code}: {response.text[:200]}"
            if response.status_code < 500:
                return result  # client error: retrying would give the same answer

        if attempt <= retries:
            log.warning("RETRY #%d in %.1fs (%s)", payload.sequence, retry_backoff, result.error)
            time.sleep(retry_backoff)
    return result


def _record_for_log(result: SendResult, sender: str, base_url: str) -> dict[str, Any]:
    local = result.local_addr or (None, None)
    remote = result.remote_addr or (None, None)
    return {
        "record_type": "client_exchange",
        "node": sender,
        "request_id": result.request_id,
        "sequence": result.sequence,
        "sent_at": result.sent_at,
        "completed_at": to_iso(utc_now()),
        "target": base_url,
        "method": "POST",
        "endpoint": ENDPOINT,
        "transport": "https" if base_url.startswith("https://") else "http",
        "tls_version": result.tls_version,
        "tls_cipher": result.tls_cipher,
        "source_ip": local[0],
        "source_port": local[1],
        "destination_ip": remote[0],
        "destination_port": remote[1],
        "status_code": result.status_code,
        "client_rtt_ms": None if result.client_rtt_ms is None else round(result.client_rtt_ms, 3),
        "server_processing_ms": result.server_processing_ms,
        "sender": sender,
        "receiver": result.receiver,
        "attempts": result.attempts,
        "error": result.error,
        "payload": result.payload,
    }


def check_health(client: httpx.Client, base_url: str, sender: str) -> bool:
    url = base_url.rstrip("/") + "/health"
    try:
        response = client.get(url, headers={HEADER_REQUEST_ID: new_request_id(), HEADER_SENDER: sender})
    except httpx.ConnectError as exc:
        log.error("HEALTH %s failed: %s", url, _explain_connect_error(exc))
        if "TLS" not in _explain_connect_error(exc):
            log.error("HINT is the server running and bound to 0.0.0.0? Is the port allowed by the firewall? "
                      "Test with: curl %s  (Kali)  or  Test-NetConnection <IP> -Port <PORT>  (Windows)", url)
        return False
    except httpx.TransportError as exc:
        log.error("HEALTH %s unreachable: %s: %s", url, type(exc).__name__, exc)
        return False
    if response.status_code != 200:
        log.error("HEALTH %s returned HTTP %s", url, response.status_code)
        return False
    tls_version, tls_cipher = _tls_info(response)
    log.info("HEALTH %s ok%s", url, f" ({tls_version}, {tls_cipher})" if tls_version else "")
    return True


def parse_args(settings: Settings, argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send a controlled number of API requests with a delay.")
    parser.add_argument("--target", default=settings.target_url,
                        help="base URL, e.g. http://192.168.56.101:8000 (default: TARGET_HOST/TARGET_PORT)")
    parser.add_argument("--sender", default=settings.node_name, help="name of this host (default: NODE_NAME)")
    parser.add_argument("--count", type=int, default=settings.default_count,
                        help=f"number of requests, 1..{MAX_COUNT} (default: DEFAULT_REQUEST_COUNT)")
    parser.add_argument("--delay", type=float, default=settings.default_delay,
                        help="seconds between requests (default: DEFAULT_DELAY_SECONDS)")
    parser.add_argument("--timeout", type=float, default=settings.request_timeout, help="per-request timeout in seconds")
    parser.add_argument("--retries", type=int, default=settings.request_retries, help="retries per request (0 = none)")
    parser.add_argument("--retry-backoff", type=float, default=settings.retry_backoff, help="seconds between retries")
    parser.add_argument("--message", default=None, help="custom message text")
    parser.add_argument("--skip-health", action="store_true", help="do not call /health before sending")
    parser.add_argument("--log-file", type=Path, default=settings.log_dir / "client-events.jsonl",
                        help="where to append client records")
    parser.add_argument("--ca-file", type=Path, default=settings.tls_ca_file,
                        help="CA certificate to trust for https targets (default: TLS_CA_FILE)")
    args = parser.parse_args(argv)

    if not args.target:
        parser.error("no target: pass --target http://<IP>:<PORT> or set TARGET_HOST in .env")
    if not args.target.startswith(("http://", "https://")):
        parser.error("--target must start with http:// or https://")
    if not 1 <= args.count <= MAX_COUNT:
        parser.error(f"--count must be between 1 and {MAX_COUNT}")
    if args.delay < 0:
        parser.error("--delay must be >= 0")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if not 0 <= args.retries <= 10:
        parser.error("--retries must be between 0 and 10")
    if not re.match(NODE_NAME_PATTERN, args.sender.lower()):
        parser.error("--sender must be lowercase letters/digits/dash, e.g. windows or kali")
    args.sender = args.sender.lower()
    return args


def run(args: argparse.Namespace) -> int:
    log.info("CLIENT sender=%s target=%s count=%d delay=%.1fs timeout=%.1fs retries=%d",
             args.sender, args.target, args.count, args.delay, args.timeout, args.retries)
    if args.delay < 1:
        log.warning("WARNING delay < 1s; keep delays reasonable in the lab")

    try:
        verify = build_verify(args.target, args.ca_file)
    except (FileNotFoundError, ssl.SSLError) as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2

    results: list[SendResult] = []
    with httpx.Client(timeout=args.timeout, verify=verify) as client:
        if not args.skip_health and not check_health(client, args.target, args.sender):
            return 2
        try:
            for seq in range(1, args.count + 1):
                payload = build_payload(args.sender, seq, args.message)
                result = send_one(client, args.target, payload, args.retries, args.retry_backoff)
                results.append(result)
                append_jsonl(args.log_file, _record_for_log(result, args.sender, args.target))
                if result.ok:
                    log.info("RESPONSE #%d status=%s latency=%.1fms server_processing=%.1fms receiver=%s",
                             seq, result.status_code, result.client_rtt_ms, result.server_processing_ms or 0,
                             result.receiver)
                else:
                    log.error("FAILED #%d request_id=%s status=%s error=%s",
                              seq, result.request_id, result.status_code, result.error)
                if seq < args.count:
                    log.info("WAIT %.1fs", args.delay)
                    time.sleep(args.delay)
        except KeyboardInterrupt:
            log.warning("INTERRUPTED by user")

    return _summary(results, args.count)


def _summary(results: list[SendResult], planned: int) -> int:
    ok = [r for r in results if r.ok]
    log.info("SUMMARY planned=%d sent=%d ok=%d failed=%d", planned, len(results), len(ok), len(results) - len(ok))
    if ok:
        rtts = [r.client_rtt_ms for r in ok if r.client_rtt_ms is not None]
        procs = [r.server_processing_ms for r in ok if r.server_processing_ms is not None]
        log.info("SUMMARY client_rtt min=%.1fms avg=%.1fms max=%.1fms | server_processing avg=%.1fms",
                 min(rtts), statistics.mean(rtts), max(rtts), statistics.mean(procs) if procs else 0.0)
    return 0 if results and len(ok) == len(results) == planned else 1


def main(argv: list[str] | None = None) -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2
    return run(parse_args(settings, argv))


if __name__ == "__main__":
    sys.exit(main())
