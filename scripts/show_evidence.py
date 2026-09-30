"""Show, per request, the evidence in ONE host's logs: who sent it, which encryption layers were
used, whether THIS host decrypted it, and what the network capture saw.

    python scripts/show_evidence.py logs/phase346c            (Windows: python, Kali: python3)
    python scripts/show_evidence.py logs --last 3 --full
    python3 scripts/show_evidence.py logs --events logs/phase346b-api-events.jsonl   (custom observer --output)

Reads whatever exists in the folder: server-events.jsonl (API server / Ollama gateway),
client-events.jsonl (traffic generator / LLM client), api-events.jsonl (observer events) and
capture-events.jsonl (wire records). Keys are never logged, so none are shown.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

SERVER_TYPES = ("server_exchange", "llm_gateway_exchange")
CLIENT_TYPES = ("client_exchange", "llm_client_exchange")
WINDOW_MARGIN_S = 5.0  # capture records this far before/after the shown requests still count


def load(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a line cut off by a crash; skip it
    return rows


def short(text: Any, limit: int) -> str:
    text = " ".join(str(text).split()) if text is not None else "-"
    return text if len(text) <= limit else text[: limit - 3] + "..."


def yes_no(value: Any) -> str:
    return "YES" if value else "no"


def describe(rid: str, server: dict | None, client: dict | None, event: dict | None, full: bool) -> list[str]:
    any_rec = server or client or event or {}
    sender = (server or {}).get("sender") or (client or {}).get("sender") or "?"
    receiver = (server or {}).get("receiver") or (client or {}).get("receiver") or "?"
    path = any_rec.get("http_path") or any_rec.get("endpoint")
    status = any_rec.get("status_code")
    llm = (server or {}).get("llm") or (client or {}).get("llm") or (event or {}).get("llm") or {}
    enc = any_rec.get("app_encryption") or (event or {}).get("app_encryption")
    limit = 10_000 if full else 90

    lines = [f"== {rid} | {sender} -> {receiver} | {any_rec.get('method', 'POST')} {path} | status {status}"]
    tls = (client or {}).get("tls_version") or (event or {}).get("tls_version")
    lines.append(f"  transport (layer 1)  : {any_rec.get('transport') or (event or {}).get('transport') or '?'}"
                 f"{' ' + tls if tls else ''}")
    if enc:
        lines.append(f"  payload   (layer 2)  : {enc}, key_id {any_rec.get('key_id')}, "
                     f"request ciphertext {any_rec.get('ciphertext_bytes')} B")
    else:
        lines.append("  payload   (layer 2)  : none (payload only protected by the transport, if at all)")

    if server:
        role = "gateway" if server.get("record_type") == "llm_gateway_exchange" else "server"
        lines.append(f"  THIS HOST as {role} (receiver):")
        if enc:
            lines.append(f"    decrypted here      : {server.get('decryption_status')}")
        lines.append(f"    plaintext visible   : {yes_no((server.get('payload') or {}).get('message') or llm.get('prompt'))}")
        if server.get("reply_encrypted_lines") is not None:
            lines.append(f"    reply sent encrypted: {server['reply_encrypted_lines']} lines, "
                         f"{server.get('reply_ciphertext_bytes')} B")
    if client:
        lines.append("  THIS HOST as client (sender):")
        lines.append(f"    server reported     : decryption {client.get('decryption_status')}")
        if client.get("encrypted_lines") is not None:
            lines.append(f"    reply received      : {client['encrypted_lines']} encrypted lines, "
                         f"decrypted here: {client.get('reply_decryption_status')}")
        if client.get("server_cert_sha256"):
            lines.append(f"    server certificate  : sha256 {client['server_cert_sha256']}")
    if event:
        wire = event.get("wire_latency_ms")
        lines.append(f"  observer (network)   : evidence {','.join(event.get('evidence', []))}; "
                     f"match {event.get('capture_match')}; wire {round(wire) if wire else '-'} ms")
    prompt = llm.get("prompt") or (server or client or {}).get("payload", {}).get("message")
    if prompt:
        lines.append(f"  prompt / message     : {short(prompt, limit)}")
    if llm.get("response"):
        lines.append(f"  answer               : {short(llm['response'], limit)}")
    if llm.get("api_style") == "openai":
        rate = llm.get("tokens_per_s")
        lines.append(f"  model timing         : not reported by the OpenAI API; tokens {llm.get('response_tokens')}, "
                     + (f"~{rate} tok/s (estimated from arrival times)" if rate else "tok/s unknown (not streamed)"))
    elif llm:
        lines.append(f"  model timing         : total {llm.get('ollama_total_ms')} ms, load {llm.get('ollama_load_ms')} ms, "
                     f"tokens {llm.get('response_tokens')}")
    return lines


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def time_window(records: list[dict[str, Any]]) -> tuple[float, float] | None:
    """Earliest start to latest end of the given log records, widened by WINDOW_MARGIN_S."""
    starts = [t for r in records if (t := _epoch(r.get("received_at") or r.get("sent_at") or r.get("timestamp")))]
    ends = [t for r in records if (t := _epoch(r.get("completed_at") or r.get("received_at") or r.get("sent_at")
                                                or r.get("timestamp")))]
    if not starts or not ends:
        return None
    return min(starts) - WINDOW_MARGIN_S, max(ends) + WINDOW_MARGIN_S


def network_view(captures: list[dict[str, Any]], texts: list[str]) -> list[str]:
    if not captures:
        return ["== network view: no capture-events.jsonl in this folder"]
    hellos = Counter(r.get("dst_port") for r in captures if r.get("kind") == "tls_client_hello")
    server_ports = {p for p, _ in hellos.most_common(3)} or {8443, 8000}
    sizes = Counter(r.get("tls_bytes") for r in captures
                    if r.get("kind") == "tls_app_data" and r.get("src_port") in server_ports)
    kinds = Counter(r.get("kind") for r in captures)
    blob = json.dumps(captures, ensure_ascii=False)
    leaked = [t for t in texts if t in blob]
    lines = ["== network view (what a wire observer sees on this host)",
             f"  records: {dict(kinds)}"]
    if sizes:
        top = ", ".join(f"{size} B x{count}" for size, count in sizes.most_common(6))
        lines.append(f"  encrypted answer records by size: {top}  ({len(sizes)} distinct sizes)")
    lines.append(f"  logged prompt/answer text found in the capture: "
                 f"{'YES - plaintext on the wire!' if leaked else 'NO (only sizes and timing are visible)'}")
    for text in leaked[:3]:
        lines.append(f"    e.g. {short(text, 60)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Per-request encryption/decryption evidence from one host's logs")
    parser.add_argument("log_dir", type=Path, help="folder with *-events.jsonl, e.g. logs/phase346c")
    parser.add_argument("--last", type=int, default=0, help="only the last N requests (default: all)")
    parser.add_argument("--full", action="store_true", help="show full prompt and answer")
    parser.add_argument("--events", type=Path, default=None,
                        help="observer events file if not <log_dir>/api-events.jsonl (observer --output)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # Windows consoles cannot print every character

    d = args.log_dir
    servers = {r["request_id"]: r for r in load(d / "server-events.jsonl")
               if r.get("record_type") in SERVER_TYPES and r.get("request_id")}
    clients = {r["request_id"]: r for r in load(d / "client-events.jsonl")
               if r.get("record_type") in CLIENT_TYPES and r.get("request_id")}
    events = {e["request_id"]: e for e in load(args.events or d / "api-events.jsonl") if e.get("request_id")}
    captures = load(d / "capture-events.jsonl")
    if not (servers or clients or events or captures):
        print(f"no logs found in {d}")
        return 1

    def when(rid: str) -> str:
        rec = servers.get(rid) or clients.get(rid) or events.get(rid) or {}
        return rec.get("received_at") or rec.get("sent_at") or rec.get("timestamp") or ""

    # Only real API requests (health checks carry no payload and are skipped).
    rids = [rid for rid in {*servers, *clients, *events}
            if ((servers.get(rid) or clients.get(rid) or events.get(rid) or {}).get("endpoint") or "") != "/health"]
    rids.sort(key=when)
    if args.last:
        rids = rids[-args.last:]

    # Network view only for the capture records around the requests shown (a log folder often holds
    # many test runs). Logs and capture come from the same host, so their clocks agree.
    window = time_window([servers.get(r) or clients.get(r) or events.get(r) or {} for r in rids])
    if window and captures:
        start, end = window
        in_window = [c for c in captures
                     if not isinstance(c.get("timestamp"), (int, float)) or start <= c["timestamp"] <= end]
        print(f"(network view limited to {len(in_window)} of {len(captures)} capture records, "
              f"the time span of the requests shown +/- {WINDOW_MARGIN_S:.0f} s)\n")
        captures = in_window

    texts: list[str] = []
    for rid in rids:
        print("\n".join(describe(rid, servers.get(rid), clients.get(rid), events.get(rid), args.full)))
        print()
        for rec in (servers.get(rid), clients.get(rid)):
            llm = (rec or {}).get("llm") or {}
            for text in (llm.get("prompt"), (llm.get("response") or "")[:40],
                         ((rec or {}).get("payload") or {}).get("message")):
                if text and len(text) >= 8:
                    texts.append(text)
    print("\n".join(network_view(captures, texts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
