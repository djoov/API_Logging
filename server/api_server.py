"""Lab API server.

Run from the project root:
    python server/api_server.py                  # uses APP_HOST / APP_PORT / NODE_NAME from .env
    python server/api_server.py --port 8001 --node-name kali
"""
from __future__ import annotations

import argparse
import asyncio
import os
import socket
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Awaitable, Callable

if __package__ in (None, ""):  # allow "python server/api_server.py"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from fastapi import FastAPI, Request, Response

from common.config import ConfigError, Settings, load_settings
from common.jsonl import append_jsonl
from common.logging_utils import get_logger, to_iso, utc_now
from models.schemas import (
    HEADER_PROCESSING_MS,
    HEADER_RECEIVER,
    HEADER_REQUEST_ID,
    HEADER_SENDER,
    ApiTestRequest,
    ApiTestResponse,
    HealthResponse,
    is_valid_request_id,
    new_request_id,
)

log = get_logger("server")


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="API Observability Lab", version="0.1.0")
    events_path = settings.log_dir / "server-events.jsonl"

    @app.middleware("http")
    async def observe_requests(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # perf_counter is monotonic, so it is the right clock for durations.
        request.state.start = time.perf_counter()
        request.state.received_at = utc_now()
        client_ip = request.client.host if request.client else None
        client_port = request.client.port if request.client else None
        header_rid = request.headers.get(HEADER_REQUEST_ID)
        header_sender = request.headers.get(HEADER_SENDER)

        log.info(
            "REQUEST %s %s from=%s:%s request_id=%s sender=%s",
            request.method, request.url.path, client_ip, client_port,
            header_rid or "-", header_sender or "-",
        )

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            log.exception("ERROR unhandled exception while processing %s", request.url.path)
            raise

        elapsed_ms = (time.perf_counter() - request.state.start) * 1000
        # The endpoint stores the exact value it returned; fall back to the middleware timing
        # for responses that never reached an endpoint (e.g. 422 validation errors).
        processing_ms = getattr(request.state, "processing_time_ms", None) or elapsed_ms

        # Body request_id wins; header is used when the body was invalid; otherwise generate one
        # so that every exchange (including /health) is correlatable.
        request_id = getattr(request.state, "request_id", None)
        if request_id is None and header_rid and is_valid_request_id(header_rid):
            request_id = header_rid
        request_id = request_id or new_request_id()

        response.headers[HEADER_REQUEST_ID] = request_id
        response.headers[HEADER_RECEIVER] = settings.node_name
        response.headers[HEADER_PROCESSING_MS] = f"{processing_ms:.3f}"

        payload: dict[str, Any] = getattr(request.state, "payload_meta", {})
        server_addr = request.scope.get("server") or (None, None)
        append_jsonl(events_path, {
            "record_type": "server_exchange",
            "node": settings.node_name,
            "request_id": request_id,
            "received_at": to_iso(request.state.received_at),
            "completed_at": to_iso(utc_now()),
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_ip": server_addr[0],
            "destination_port": server_addr[1],
            "method": request.method,
            "endpoint": request.url.path,
            "transport": request.url.scheme,  # "http" or "https"
            "status_code": status_code,
            "server_processing_ms": round(processing_ms, 3),
            "sender": payload.get("sender") or header_sender,
            "receiver": settings.node_name,
            "payload": payload,
        })

        log.info(
            "RESPONSE request_id=%s status=%s processing=%.1fms",
            request_id, status_code, processing_ms,
        )
        return response

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.post("/api/test", response_model=ApiTestResponse)
    async def api_test(body: ApiTestRequest, request: Request) -> ApiTestResponse:
        request.state.request_id = body.request_id
        request.state.payload_meta = {
            "message": body.message[:200],
            "sender": body.sender,
            "sequence": body.sequence,
            "sent_at": to_iso(body.sent_at),
        }
        if settings.simulated_work_ms > 0:
            # Optional artificial work, to make server time vs. network time visible.
            await asyncio.sleep(settings.simulated_work_ms / 1000)

        processing_ms = (time.perf_counter() - request.state.start) * 1000
        request.state.processing_time_ms = processing_ms
        return ApiTestResponse(
            status="ok",
            message="received",
            receiver=settings.node_name,
            request_id=body.request_id,
            sequence=body.sequence,
            received_at=request.state.received_at,
            processing_time_ms=round(processing_ms, 3),
        )

    return app


def _parse_args(settings: Settings, argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab API server")
    parser.add_argument("--host", default=settings.app_host, help="bind address (default: APP_HOST)")
    parser.add_argument("--port", type=int, default=settings.app_port, help="bind port (default: APP_PORT)")
    parser.add_argument("--node-name", default=settings.node_name, help="this host's name (default: NODE_NAME)")
    # Experiment switches (defaults keep the original behaviour):
    parser.add_argument("--tcp-nodelay", action=argparse.BooleanOptionalAction, default=settings.server_tcp_nodelay,
                        help="disable Nagle on accepted connections (default: SERVER_TCP_NODELAY, off)")
    parser.add_argument("--keep-alive", type=int, default=settings.server_keep_alive,
                        help="idle keep-alive timeout in seconds (default: SERVER_KEEP_ALIVE_SECONDS, 5)")
    return parser.parse_args(argv)


def make_listening_socket(host: str, port: int, tcp_nodelay: bool) -> socket.socket:
    """Bind the listening socket ourselves so TCP_NODELAY can be set on it.

    Accepted connections inherit TCP_NODELAY from the listening socket (checked on Windows and
    Linux). asyncio tries to set it per connection too, but on Windows the accepted socket reports
    proto=0 and asyncio silently skips it, so Nagle stays ON there unless set here.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    if os.name == "posix":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # not on Windows: allows port hijacking
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if tcp_nodelay else 0)
    sock.bind((host, port))
    return sock


def main(argv: list[str] | None = None) -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2
    args = _parse_args(settings, argv)
    settings = replace(settings, app_host=args.host, app_port=args.port, node_name=args.node_name.lower())

    tls_kwargs: dict[str, str] = {}
    if bool(settings.tls_cert_file) != bool(settings.tls_key_file):
        log.error("CONFIG ERROR set both TLS_CERT_FILE and TLS_KEY_FILE (or neither for plain HTTP)")
        return 2
    if settings.server_tls:
        assert settings.tls_cert_file and settings.tls_key_file
        for label, path in (("TLS_CERT_FILE", settings.tls_cert_file), ("TLS_KEY_FILE", settings.tls_key_file)):
            if not path.is_file():
                log.error("CONFIG ERROR %s not found: %s (create it with scripts/make_certs.py)", label, path)
                return 2
        tls_kwargs = {"ssl_certfile": str(settings.tls_cert_file), "ssl_keyfile": str(settings.tls_key_file)}

    scheme = "https" if tls_kwargs else "http"
    log.info("SERVER node=%s listening on %s://%s:%s", settings.node_name, scheme, settings.app_host, settings.app_port)
    if tls_kwargs:
        log.info("SERVER TLS certificate %s", settings.tls_cert_file)
    log.info("SERVER tcp_nodelay=%s keep_alive=%ss",
             "forced on" if args.tcp_nodelay else "not forced (asyncio default: Nagle stays on under Windows)",
             args.keep_alive)
    log.info("SERVER app events -> %s", settings.log_dir / "server-events.jsonl")
    config = uvicorn.Config(
        create_app(settings),
        host=settings.app_host,
        port=settings.app_port,
        log_level="warning",  # our middleware already logs every request
        access_log=False,
        timeout_keep_alive=args.keep_alive,
        **tls_kwargs,  # type: ignore[arg-type]
    )
    try:
        sockets = None
        if args.tcp_nodelay:
            sockets = [make_listening_socket(settings.app_host, settings.app_port, tcp_nodelay=True)]
        uvicorn.Server(config).run(sockets=sockets)
    except OSError as exc:
        log.error("SERVER cannot listen on %s:%s: %s", settings.app_host, settings.app_port, exc)
        return 2
    except KeyboardInterrupt:
        pass
    log.info("SERVER stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
