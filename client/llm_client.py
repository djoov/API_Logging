"""PHASE 6: send prompts to Ollama through the HTTPS gateway and log prompt + full answer.

    python client/llm_client.py --prompt "Jelaskan TCP handshake"
    python client/llm_client.py --prompts-file prompts.txt --count 3 --delay 5 --endpoint chat
    python client/llm_client.py --no-stream --model llama3.2
    python client/llm_client.py --app-encrypt           # Phase 3/4: whole Ollama request Fernet-encrypted

Every exchange is written to logs/client-events.jsonl (record_type "llm_client_exchange") with the
prompt, the complete answer (streamed pieces joined together), time to first token and total time.
There are no automatic retries: an LLM request is expensive and not idempotent.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from client.traffic_generator import _explain_connect_error, _socket_addresses, _tls_info, build_verify, check_health
from common.config import ConfigError, Settings, load_settings
from common.jsonl import append_jsonl
from common.logging_utils import get_logger, to_iso, utc_now
from llm.ollama_protocol import OllamaResponseAssembler
from models.schemas import (
    HEADER_DECRYPTION,
    HEADER_RECEIVER,
    HEADER_REQUEST_ID,
    HEADER_SENDER,
    NODE_NAME_PATTERN,
    new_request_id,
)
from security.payload_crypto import ALGORITHM, PayloadCryptoError, decrypt_payload, encrypt_payload, key_id, load_key

log = get_logger("llm-client")

DEFAULT_PROMPTS = [
    "Jelaskan secara singkat apa itu TCP handshake.",
    "Apa perbedaan HTTP dan HTTPS dalam satu paragraf?",
    "Sebutkan tiga metrik penting untuk memantau API.",
]
MAX_COUNT = 100
SECURE_PREFIX = "/secure"  # gateway path for app-layer encrypted requests


@dataclass
class LlmResult:
    sequence: int
    request_id: str
    prompt: str
    sent_at: str = ""
    status_code: int | None = None
    receiver: str | None = None
    ttft_ms: float | None = None
    total_ms: float | None = None
    response: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    local_addr: Any = None
    remote_addr: Any = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    # Phase 3/4
    app_encryption: str | None = None
    key_id: str | None = None
    ciphertext_bytes: int | None = None
    decryption_status: str | None = None  # reported by the gateway (X-Decryption-Status)
    encrypted_lines: int = 0  # encrypted NDJSON pieces received
    http_path: str = ""  # actual HTTP path used (/api/... or /secure/api/...)

    @property
    def ok(self) -> bool:
        return self.status_code == 200 and self.error is None


def build_body(endpoint: str, model: str, prompt: str, stream: bool) -> dict[str, Any]:
    if endpoint == "/api/chat":
        return {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": stream}
    return {"model": model, "prompt": prompt, "stream": stream}


def build_secure_envelope(body: dict[str, Any], request_id: str, sender: str, sequence: int, sent_at: str,
                          app_key: bytes) -> dict[str, Any]:
    """Phase 3/4: the whole Ollama request (model, prompt, options) goes inside the ciphertext."""
    return {"request_id": request_id, "sender": sender, "sequence": sequence, "sent_at": sent_at,
            "enc": ALGORITHM, "key_id": key_id(app_key), "ciphertext": encrypt_payload(body, app_key)}


def _open_line(line: str, app_key: bytes) -> str:
    """Decrypt one encrypted NDJSON line from the gateway; plain lines (gateway errors) pass through."""
    obj = json.loads(line)
    if isinstance(obj, dict) and obj.get("ciphertext"):
        return json.dumps(decrypt_payload(obj["ciphertext"], app_key))
    if isinstance(obj, dict) and "detail" in obj and "error" not in obj:
        return json.dumps({"error": str(obj["detail"])})
    return line


def send_prompt(client: httpx.Client, base_url: str, endpoint: str, model: str, prompt: str, stream: bool,
                sender: str, sequence: int, show: bool = False, app_key: bytes | None = None) -> LlmResult:
    result = LlmResult(sequence=sequence, request_id=new_request_id(), prompt=prompt, sent_at=to_iso(utc_now()))
    headers = {HEADER_REQUEST_ID: result.request_id, HEADER_SENDER: sender}
    assembler = OllamaResponseAssembler(endpoint)
    body: dict[str, Any] = build_body(endpoint, model, prompt, stream)
    path = endpoint
    if app_key:
        body = build_secure_envelope(body, result.request_id, sender, sequence, result.sent_at, app_key)
        path = SECURE_PREFIX + endpoint
        result.app_encryption, result.key_id = ALGORITHM, body["key_id"]
        result.ciphertext_bytes = len(body["ciphertext"])
    result.http_path = path
    started = time.perf_counter()
    shown = 0
    try:
        with client.stream("POST", base_url.rstrip("/") + path, json=body, headers=headers) as response:
            result.status_code = response.status_code
            result.receiver = response.headers.get(HEADER_RECEIVER)
            result.decryption_status = response.headers.get(HEADER_DECRYPTION)
            result.local_addr, result.remote_addr = _socket_addresses(response)
            result.tls_version, result.tls_cipher = _tls_info(response)
            if app_key:
                # Each streamed piece is its own encrypted line: decrypt as they arrive.
                for line in response.iter_lines():
                    if not line.strip():
                        continue
                    result.encrypted_lines += 1
                    assembler.feed_line(_open_line(line, app_key), time.perf_counter())
                    if show and len(assembler.text) > shown:
                        print(assembler.text[shown:], end="", flush=True)
                        shown = len(assembler.text)
            else:
                for chunk in response.iter_raw():
                    assembler.feed_bytes(chunk, time.perf_counter())
                    if show and len(assembler.text) > shown:
                        print(assembler.text[shown:], end="", flush=True)
                        shown = len(assembler.text)
                assembler.close(time.perf_counter())
    except httpx.ConnectError as exc:
        result.error = _explain_connect_error(exc)
    except PayloadCryptoError as exc:
        result.error = f"could not decrypt the gateway's answer: {exc}"
    except httpx.TimeoutException as exc:
        result.error = f"timeout after waiting for the model: {type(exc).__name__}"
    except httpx.TransportError as exc:
        result.error = f"transport error: {type(exc).__name__}: {exc}"
    if show and shown:
        print(flush=True)

    result.total_ms = round((time.perf_counter() - started) * 1000, 3)
    if assembler.first_chunk_at is not None:
        result.ttft_ms = round((assembler.first_chunk_at - started) * 1000, 3)
    result.response = assembler.text
    result.summary = assembler.summary()
    if result.error is None and assembler.error:
        result.error = assembler.error  # e.g. Ollama: model not found
    if result.error is None and result.status_code not in (None, 200):
        result.error = f"HTTP {result.status_code}"
    return result


def _record(result: LlmResult, args: argparse.Namespace) -> dict[str, Any]:
    local = result.local_addr or (None, None)
    remote = result.remote_addr or (None, None)
    return {
        "record_type": "llm_client_exchange",
        "node": args.sender,
        "request_id": result.request_id,
        "sequence": result.sequence,
        "sent_at": result.sent_at,
        "completed_at": to_iso(utc_now()),
        "target": args.target,
        "method": "POST",
        "endpoint": args.endpoint,  # Ollama API endpoint
        "http_path": result.http_path,  # actual HTTP path
        "transport": "https" if args.target.startswith("https://") else "http",
        "tls_version": result.tls_version,
        "tls_cipher": result.tls_cipher,
        "source_ip": local[0],
        "source_port": local[1],
        "destination_ip": remote[0],
        "destination_port": remote[1],
        "status_code": result.status_code,
        "client_rtt_ms": result.total_ms,
        "app_encryption": result.app_encryption,
        "key_id": result.key_id,
        "ciphertext_bytes": result.ciphertext_bytes,
        "decryption_status": result.decryption_status,
        "sender": args.sender,
        "receiver": result.receiver,
        "attempts": 1,
        "error": result.error,
        "payload": {"message": result.prompt[:200], "sender": args.sender, "sequence": result.sequence},
        "llm": {
            **result.summary,
            "model": args.model,
            "prompt": result.prompt,
            "response": result.response,
            "stream": args.stream,
            "client_ttft_ms": result.ttft_ms,
            "client_total_ms": result.total_ms,
        },
    }


def load_prompts(args: argparse.Namespace) -> list[str]:
    prompts = list(args.prompt or [])
    if args.prompts_file:
        lines = args.prompts_file.read_text(encoding="utf-8").splitlines()
        prompts += [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    return prompts or DEFAULT_PROMPTS


def parse_args(settings: Settings, argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send prompts to Ollama via the HTTPS gateway and log everything")
    parser.add_argument("--target", default=settings.llm_target_url,
                        help="gateway URL, e.g. https://192.168.56.1:8443 (default: LLM_TARGET_URL)")
    parser.add_argument("--endpoint", choices=["generate", "chat"], default="generate",
                        help="Ollama API: /api/generate (default) or /api/chat")
    parser.add_argument("--model", default=settings.llm_model, help="model name (default: LLM_MODEL)")
    parser.add_argument("--prompt", action="append", help="prompt text (repeatable)")
    parser.add_argument("--prompts-file", type=Path, help="text file, one prompt per line")
    parser.add_argument("--count", type=int, default=None, help="number of requests (default: one per prompt)")
    parser.add_argument("--delay", type=float, default=settings.default_delay, help="seconds between requests")
    parser.add_argument("--stream", action=argparse.BooleanOptionalAction, default=True,
                        help="stream the answer piece by piece (Ollama default)")
    parser.add_argument("--show", action=argparse.BooleanOptionalAction, default=True,
                        help="print the answer live in the terminal")
    parser.add_argument("--timeout", type=float, default=settings.llm_timeout, help="seconds to wait for the model")
    parser.add_argument("--keep-alive", type=float, default=settings.client_keep_alive,
                        help="seconds an idle connection is kept for reuse")
    parser.add_argument("--ca-file", type=Path, default=settings.tls_ca_file, help="lab CA (default: TLS_CA_FILE)")
    parser.add_argument("--app-encrypt", action="store_true",
                        help="Phase 3/4: encrypt the whole Ollama request and use the gateway's /secure path")
    parser.add_argument("--key-file", type=Path, default=settings.fernet_key_file,
                        help="Fernet key for --app-encrypt (default: FERNET_KEY_FILE)")
    parser.add_argument("--sender", default=settings.node_name, help="this host's name (default: NODE_NAME)")
    parser.add_argument("--skip-health", action="store_true")
    parser.add_argument("--log-file", type=Path, default=settings.log_dir / "client-events.jsonl")
    args = parser.parse_args(argv)

    if not args.target:
        parser.error("no target: pass --target https://<GATEWAY_IP>:8443 or set LLM_TARGET_URL in .env")
    if not args.target.startswith(("http://", "https://")):
        parser.error("--target must start with http:// or https://")
    if args.count is not None and not 1 <= args.count <= MAX_COUNT:
        parser.error(f"--count must be between 1 and {MAX_COUNT}")
    if args.delay < 0 or args.timeout <= 0 or args.keep_alive < 0:
        parser.error("--delay/--keep-alive must be >= 0 and --timeout > 0")
    if not re.match(NODE_NAME_PATTERN, args.sender.lower()):
        parser.error("--sender must be lowercase letters/digits/dash")
    args.sender = args.sender.lower()
    args.endpoint = f"/api/{args.endpoint}"
    return args


def run(args: argparse.Namespace) -> int:
    prompts = load_prompts(args)
    count = args.count or len(prompts)
    log.info("LLM CLIENT sender=%s target=%s endpoint=%s model=%s stream=%s count=%d delay=%.1fs timeout=%.0fs",
             args.sender, args.target, args.endpoint, args.model, args.stream, count, args.delay, args.timeout)
    try:
        verify = build_verify(args.target, args.ca_file)
    except FileNotFoundError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2
    app_key: bytes | None = None
    if args.app_encrypt:
        try:
            app_key = load_key(args.key_file)
        except PayloadCryptoError as exc:
            log.error("CONFIG ERROR %s (create one with scripts/make_fernet_key.py)", exc)
            return 2
        log.info("LLM CLIENT app-layer encryption: fernet key_id=%s -> %s%s", key_id(app_key), SECURE_PREFIX,
                 args.endpoint)

    results: list[LlmResult] = []
    timeout = httpx.Timeout(args.timeout, connect=5.0)
    with httpx.Client(timeout=timeout, verify=verify, limits=httpx.Limits(keepalive_expiry=args.keep_alive)) as client:
        if not args.skip_health and not check_health(client, args.target, args.sender):
            return 2
        try:
            for seq in range(1, count + 1):
                prompt = prompts[(seq - 1) % len(prompts)]
                log.info('SEND #%d model=%s prompt="%s"', seq, args.model, prompt[:80])
                result = send_prompt(client, args.target, args.endpoint, args.model, prompt, args.stream,
                                     args.sender, seq, show=args.show, app_key=app_key)
                results.append(result)
                append_jsonl(args.log_file, _record(result, args))
                s = result.summary
                if result.ok:
                    log.info("RESPONSE #%d status=200 ttft=%s total=%.0fms tokens=%s tok/s=%s request_id=%s%s",
                             seq, f"{result.ttft_ms:.0f}ms" if result.ttft_ms is not None else "-", result.total_ms,
                             s.get("response_tokens"), s.get("tokens_per_s"), result.request_id,
                             f" decryption={result.decryption_status} encrypted_lines={result.encrypted_lines}"
                             if app_key else "")
                else:
                    log.error("FAILED #%d status=%s error=%s request_id=%s", seq, result.status_code,
                              result.error, result.request_id)
                if seq < count:
                    log.info("WAIT %.1fs", args.delay)
                    time.sleep(args.delay)
        except KeyboardInterrupt:
            log.warning("INTERRUPTED by user")

    ok = [r for r in results if r.ok]
    log.info("SUMMARY planned=%d sent=%d ok=%d failed=%d", count, len(results), len(ok), len(results) - len(ok))
    if ok:
        ttfts = [r.ttft_ms for r in ok if r.ttft_ms is not None]
        totals = [r.total_ms for r in ok if r.total_ms is not None]
        log.info("SUMMARY ttft avg=%s | total avg=%.0fms max=%.0fms",
                 f"{statistics.mean(ttfts):.0f}ms" if ttfts else "-", statistics.mean(totals), max(totals))
    return 0 if results and len(ok) == len(results) == count else 1


def main(argv: list[str] | None = None) -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2
    return run(parse_args(settings, argv))


if __name__ == "__main__":
    sys.exit(main())
