"""PHASE 4: HTTPS gateway in front of Ollama that logs every prompt and answer.

    client ──HTTPS──▶ gateway (TLS terminates here, full prompt/answer logged) ──HTTP──▶ Ollama on 127.0.0.1

Ollama itself speaks only plain HTTP and should stay bound to 127.0.0.1:11434. This gateway is
the only thing exposed on the lab network. It is the legitimate decryption point: it owns the
server certificate/key, so it sees the plaintext request and response and writes them to
logs/server-events.jsonl (record_type "llm_gateway_exchange").

    python gateway/ollama_gateway.py                     # uses GATEWAY_*, OLLAMA_URL, TLS_* from .env
    python gateway/ollama_gateway.py --ollama-url http://127.0.0.1:11434 --port 8443
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlparse

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from common.config import ConfigError, Settings, load_settings
from common.jsonl import append_jsonl
from common.logging_utils import get_logger, to_iso, utc_now
from llm.ollama_protocol import LLM_ENDPOINTS, OllamaResponseAssembler, extract_prompt
from models.schemas import HEADER_RECEIVER, HEADER_REQUEST_ID, HEADER_SENDER, is_valid_request_id, new_request_id
from server.api_server import make_listening_socket

log = get_logger("gateway")

PASS_THROUGH_GET = ("/api/tags", "/api/version")  # read-only Ollama endpoints, also logged


def _preview(text: str | None, limit: int = 70) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def create_gateway_app(settings: Settings) -> FastAPI:
    events_path = settings.log_dir / "server-events.jsonl"
    upstream_base = settings.ollama_url

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Long read timeout: an LLM may think for minutes before and while answering.
        timeout = httpx.Timeout(settings.llm_timeout, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            app.state.ollama = client
            yield

    app = FastAPI(title="Ollama observability gateway", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async def proxy(request: Request, endpoint: str) -> Response:
        received_at = utc_now()
        started = time.perf_counter()
        header_rid = request.headers.get(HEADER_REQUEST_ID)
        request_id = header_rid if header_rid and is_valid_request_id(header_rid) else new_request_id()
        sender = request.headers.get(HEADER_SENDER)
        client_ip = request.client.host if request.client else None
        client_port = request.client.port if request.client else None
        server_addr = request.scope.get("server") or (None, None)
        reply_headers = {HEADER_REQUEST_ID: request_id, HEADER_RECEIVER: settings.node_name}

        raw = await request.body()
        body: dict[str, Any] = {}
        if raw:
            try:
                parsed = json.loads(raw)
                body = parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return JSONResponse({"error": "request body is not valid JSON"}, status_code=400, headers=reply_headers)
        is_llm = endpoint in LLM_ENDPOINTS
        prompt = extract_prompt(endpoint, body) if is_llm else None
        model = body.get("model")
        stream = bool(body.get("stream", True)) if is_llm else False

        log.info("REQUEST %s %s from=%s:%s request_id=%s sender=%s%s", request.method, endpoint, client_ip,
                 client_port, request_id, sender or "-",
                 f' model={model} stream={stream} prompt="{_preview(prompt)}"' if is_llm else "")

        def write_record(status: int, assembler: OllamaResponseAssembler | None, error: str | None) -> None:
            total_ms = (time.perf_counter() - started) * 1000
            llm: dict[str, Any] | None = None
            if is_llm:
                summary = assembler.summary() if assembler else {}
                ttft = (assembler.first_chunk_at - started) * 1000 if assembler and assembler.first_chunk_at else None
                llm = {
                    **summary,
                    "model": model or summary.get("model"),
                    "prompt": prompt,
                    "response": assembler.text if assembler else None,
                    "stream": stream,
                    "gateway_ttft_ms": None if ttft is None else round(ttft, 3),
                    "gateway_total_ms": round(total_ms, 3),
                    "upstream": upstream_base,
                }
                error = error or summary.get("error")
            append_jsonl(events_path, {
                "record_type": "llm_gateway_exchange",
                "node": settings.node_name,
                "request_id": request_id,
                "received_at": to_iso(received_at),
                "completed_at": to_iso(utc_now()),
                "source_ip": client_ip,
                "source_port": client_port,
                "destination_ip": server_addr[0],
                "destination_port": server_addr[1],
                "method": request.method,
                "endpoint": endpoint,
                "transport": request.url.scheme,
                "status_code": status,
                "server_processing_ms": round(total_ms, 3),  # gateway view: includes Ollama's time
                "sender": sender,
                "receiver": settings.node_name,
                "payload": {"message": _preview(prompt, 200) if prompt else None, "sender": sender},
                "llm": llm,
                "error": error,
            })
            if is_llm:
                log.info('RESPONSE request_id=%s status=%s total=%.0fms ttft=%s tokens=%s tok/s=%s response="%s"%s',
                         request_id, status, total_ms,
                         f"{llm['gateway_ttft_ms']:.0f}ms" if llm and llm["gateway_ttft_ms"] is not None else "-",
                         llm.get("response_tokens") if llm else "-", llm.get("tokens_per_s") if llm else "-",
                         _preview(llm.get("response") if llm else None), f" error={error}" if error else "")
            else:
                log.info("RESPONSE request_id=%s status=%s total=%.0fms", request_id, status, total_ms)

        client: httpx.AsyncClient = request.app.state.ollama
        upstream_request = client.build_request(
            request.method, upstream_base + endpoint, content=raw or None,
            headers={"Content-Type": "application/json"} if raw else None,
        )
        try:
            upstream = await client.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            error = f"Ollama unreachable at {upstream_base}: {type(exc).__name__}: {exc}"
            write_record(502, None, error)
            return JSONResponse({"error": error}, status_code=502, headers=reply_headers)

        assembler = OllamaResponseAssembler(endpoint) if is_llm else None

        async def relay() -> AsyncIterator[bytes]:
            error: str | None = None
            try:
                # Forward each piece as soon as it arrives: streaming must stay streaming.
                async for chunk in upstream.aiter_raw():
                    if assembler:
                        assembler.feed_bytes(chunk, time.perf_counter())
                    yield chunk
                if assembler:
                    assembler.close(time.perf_counter())
            except httpx.HTTPError as exc:
                error = f"Ollama stream broke: {type(exc).__name__}: {exc}"
                raise
            except BaseException:
                error = "client disconnected before the answer finished"
                raise
            finally:
                await upstream.aclose()
                write_record(upstream.status_code, assembler, error)

        return StreamingResponse(relay(), status_code=upstream.status_code,
                                 media_type=upstream.headers.get("content-type"), headers=reply_headers)

    def route(endpoint: str) -> Any:
        async def handler(request: Request) -> Response:  # annotation tells FastAPI to inject the request
            return await proxy(request, endpoint)
        return handler

    for path in LLM_ENDPOINTS:
        app.add_api_route(path, route(path), methods=["POST"])
    for path in PASS_THROUGH_GET:
        app.add_api_route(path, route(path), methods=["GET"])
    return app


def _parse_args(settings: Settings, argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HTTPS gateway in front of Ollama that logs prompts and answers")
    parser.add_argument("--host", default=settings.gateway_host, help="bind address (default: GATEWAY_HOST)")
    parser.add_argument("--port", type=int, default=settings.gateway_port, help="bind port (default: GATEWAY_PORT, 8443)")
    parser.add_argument("--ollama-url", default=settings.ollama_url, help="upstream Ollama (default: OLLAMA_URL)")
    parser.add_argument("--node-name", default=settings.node_name)
    # Nagle stays ON under Windows otherwise (see README section 16); streaming suffers most.
    parser.add_argument("--tcp-nodelay", action=argparse.BooleanOptionalAction, default=True,
                        help="disable Nagle on client connections (default: on)")
    parser.add_argument("--keep-alive", type=int, default=settings.server_keep_alive,
                        help="idle keep-alive timeout in seconds (default: SERVER_KEEP_ALIVE_SECONDS)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2
    args = _parse_args(settings, argv)
    settings = replace(settings, node_name=args.node_name.lower(), ollama_url=args.ollama_url.rstrip("/"))

    upstream_host = urlparse(settings.ollama_url).hostname
    if upstream_host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("WARNING OLLAMA_URL points to %s; Ollama should stay on 127.0.0.1 so that only this "
                    "gateway is reachable from the network", upstream_host)

    tls_kwargs: dict[str, str] = {}
    if settings.server_tls:
        assert settings.tls_cert_file and settings.tls_key_file
        for label, path in (("TLS_CERT_FILE", settings.tls_cert_file), ("TLS_KEY_FILE", settings.tls_key_file)):
            if not path.is_file():
                log.error("CONFIG ERROR %s not found: %s (create it with scripts/make_certs.py)", label, path)
                return 2
        tls_kwargs = {"ssl_certfile": str(settings.tls_cert_file), "ssl_keyfile": str(settings.tls_key_file)}
    else:
        log.warning("WARNING no TLS_CERT_FILE/TLS_KEY_FILE: prompts and answers travel in PLAINTEXT (HTTP)")

    scheme = "https" if tls_kwargs else "http"
    log.info("GATEWAY node=%s listening on %s://%s:%s -> %s", settings.node_name, scheme, args.host, args.port,
             settings.ollama_url)
    log.info("GATEWAY tcp_nodelay=%s keep_alive=%ss timeout=%ss events -> %s", "on" if args.tcp_nodelay else "off",
             args.keep_alive, settings.llm_timeout, settings.log_dir / "server-events.jsonl")
    config = uvicorn.Config(create_gateway_app(settings), host=args.host, port=args.port, log_level="warning",
                            access_log=False, timeout_keep_alive=args.keep_alive, **tls_kwargs)  # type: ignore[arg-type]
    try:
        sockets = [make_listening_socket(args.host, args.port, tcp_nodelay=True)] if args.tcp_nodelay else None
        uvicorn.Server(config).run(sockets=sockets)
    except OSError as exc:
        log.error("GATEWAY cannot listen on %s:%s: %s", args.host, args.port, exc)
        return 2
    except KeyboardInterrupt:
        pass
    log.info("GATEWAY stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
