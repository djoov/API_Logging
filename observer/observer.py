"""API observer: correlates application logs and packet capture into logs/api-events.jsonl.

Examples (from the project root):
    python observer/observer.py --list-interfaces
    python observer/observer.py --mode app                      # app logs only, no capture tool needed
    python observer/observer.py --mode both --interface 8       # app logs + live capture
    python observer/observer.py --mode capture --read-pcap lab.pcap   # offline analysis, then exit
    python observer/observer.py --replay                        # rebuild events from existing app logs
"""
from __future__ import annotations

import argparse
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # allow "python observer/observer.py"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.config import ConfigError, Settings, load_settings
from common.jsonl import JsonlTailer, append_jsonl
from common.logging_utils import get_logger
from observer.capture_backend import CaptureBackend, CaptureError, CaptureRecord, create_backend
from observer.correlator import ExchangeCorrelator

log = get_logger("observer")

_CAPTURE_DONE = object()  # queue sentinel: capture process ended


def parse_args(settings: Settings, argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Observe API exchanges on this host.")
    parser.add_argument("--mode", choices=["app", "capture", "both"], default="both",
                        help="app = application logs, capture = packet capture, both = merge (default)")
    parser.add_argument("--backend", choices=["auto", "tshark", "tcpdump"], default=None,
                        help="capture tool (default: CAPTURE_BACKEND or auto)")
    parser.add_argument("--interface", default=settings.capture_interface,
                        help="capture interface name/number (default: OBSERVER_INTERFACE)")
    parser.add_argument("--filter", default=settings.capture_filter, help="BPF capture filter (default: CAPTURE_FILTER)")
    parser.add_argument("--read-pcap", type=Path, default=None, help="analyse a saved pcap/pcapng with TShark and exit")
    parser.add_argument("--replay", action="store_true", help="process existing app logs from the start, then exit")
    parser.add_argument("--from-start", action="store_true", help="also process lines already in the app logs")
    parser.add_argument("--duration", type=float, default=None, help="stop after N seconds (default: until Ctrl+C)")
    parser.add_argument("--node-name", default=settings.node_name, help="this host's name (default: NODE_NAME)")
    parser.add_argument("--output", type=Path, default=settings.log_dir / "api-events.jsonl")
    parser.add_argument("--list-interfaces", action="store_true", help="print capture interfaces and exit")
    https_default = settings.server_tls or settings.target_scheme == "https"
    parser.add_argument("--transport", choices=["auto", "http", "https"],
                        default="https" if https_default else "auto",
                        help="https forces TShark to decode the API port as TLS (default: https when "
                             "TLS_CERT_FILE or TARGET_SCHEME=https is set, else auto-detect)")
    return parser.parse_args(argv)


def _list_interfaces(settings: Settings, backend_name: str) -> int:
    try:
        backend = create_backend(backend_name, "", "", log, settings.tshark_path)
    except CaptureError as exc:
        log.error("CAPTURE %s", exc)
        return 2
    cmd = backend.list_interfaces_command()
    log.info("INTERFACES via: %s", subprocess.list2cmdline(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(result.stdout or result.stderr)
    log.info("Set OBSERVER_INTERFACE in .env to the number or name of the interface that "
             "carries Windows <-> Kali traffic (e.g. the VirtualBox Host-Only adapter).")
    return result.returncode


def _capture_worker(backend: CaptureBackend, out: "queue.Queue[Any]") -> None:
    try:
        for record in backend.records():
            out.put(record)
    except CaptureError as exc:
        log.error("CAPTURE %s", exc)
    except Exception as exc:  # keep the observer alive; app-log evidence still works
        log.error("CAPTURE worker crashed: %s: %s", type(exc).__name__, exc)
    finally:
        out.put(_CAPTURE_DONE)


def _log_capture(record: CaptureRecord) -> None:
    flow = f"{record.src_ip}:{record.src_port} -> {record.dst_ip}:{record.dst_port}"
    if record.kind in ("request", "response"):
        what = f"{record.method} {record.uri}" if record.kind == "request" else f"status={record.status_code}"
        log.info("WIRE %s %s stream=%s bytes=%s request_id=%s",
                 flow, what, record.tcp_stream, record.message_len, record.request_id or "-")
        return
    extra = ""
    if record.kind == "tls_server_hello":
        extra = f" version={record.tls_version} cipher={record.tls_cipher}"
    elif record.kind == "tls_client_hello":
        extra = f" sni={record.tls_sni or '-'}"
    # Encrypted: no method, URI, status or request_id is visible here.
    log.info("WIRE TLS %s %s stream=%s encrypted_bytes=%s%s",
             flow, record.kind.removeprefix("tls_"), record.tcp_stream, record.tls_bytes, extra)


def _log_event(event: dict[str, Any]) -> None:
    sender, _, receiver = event["direction"].partition("_to_")
    latency = f"{event['latency_ms']:.1f}ms ({event['latency_source']})" if event["latency_ms"] is not None else "n/a"
    tls = f" {event['tls_version']}" if event.get("tls_version") else ""
    match = f" match={event['capture_match']}" if event.get("capture_match") else ""
    if event["method"] is None and event["evidence"] == ["capture_tls"]:
        # Encrypted exchange with no app log on this host: the HTTP details are simply not visible.
        request = f"<encrypted {event['request_bytes']}B -> {event['response_bytes']}B>"
    else:
        request = f"{event['method']} {event['endpoint']}"
    log.info("OBSERVED %s -> %s [%s%s] %s status=%s latency=%s request_id=%s evidence=%s%s",
             sender, receiver, event.get("transport") or "?", tls, request,
             event["status_code"] if event["status_code"] is not None else "?", latency,
             event["request_id"] or "?", ",".join(event["evidence"]), match)


def _server_port(settings: Settings, bpf_filter: str) -> int:
    match = re.search(r"port\s+(\d+)", bpf_filter or "")
    return int(match.group(1)) if match else settings.app_port


def run(settings: Settings, args: argparse.Namespace) -> int:
    node = args.node_name.lower()
    server_port = _server_port(settings, args.filter)
    correlator = ExchangeCorrelator(node, settings.peer_names, settings.merge_window_seconds,
                                    server_port=server_port)
    use_app = args.mode in ("app", "both") and args.read_pcap is None
    use_capture = args.mode in ("capture", "both") and not args.replay
    finite = args.replay or args.read_pcap is not None  # run to completion instead of tailing

    tailers: dict[str, JsonlTailer] = {}
    if use_app:
        from_start = args.from_start or args.replay
        tailers["client"] = JsonlTailer(settings.log_dir / "client-events.jsonl", from_start)
        tailers["server"] = JsonlTailer(settings.log_dir / "server-events.jsonl", from_start)

    events_q: "queue.Queue[Any]" = queue.Queue()
    backend: CaptureBackend | None = None
    capture_running = False
    if use_capture:
        try:
            backend = create_backend(args.backend or settings.capture_backend, args.interface, args.filter,
                                     log, settings.tshark_path, args.read_pcap,
                                     tls_port=server_port if args.transport == "https" else None)
            if args.transport == "https" and backend.name == "tcpdump":
                log.warning("CAPTURE tcpdump cannot classify TLS records; install TShark, or record with "
                            "`tcpdump -w` and analyse with --read-pcap")
            backend.build_command()  # validates interface early, before starting threads
        except CaptureError as exc:
            if args.mode == "capture":
                log.error("CAPTURE %s", exc)
                return 2
            log.warning("CAPTURE disabled: %s -- continuing with application logs only", exc)
            backend = None
        if backend is not None:
            threading.Thread(target=_capture_worker, args=(backend, events_q), daemon=True).start()
            capture_running = True

    log.info("OBSERVER node=%s mode=%s capture=%s transport=%s server_port=%s output=%s", node, args.mode,
             backend.name if backend else "off", args.transport, server_port, args.output)
    if use_app:
        log.info("OBSERVER reading %s and %s", tailers["client"].path, tailers["server"].path)

    written = 0
    deadline = time.monotonic() + args.duration if args.duration else None
    try:
        while True:
            for source, tailer in tailers.items():
                for rec in tailer.read_new():
                    if source == "client":
                        correlator.add_client_record(rec)
                    else:
                        correlator.add_server_record(rec)

            while True:
                try:
                    item = events_q.get_nowait()
                except queue.Empty:
                    break
                if item is _CAPTURE_DONE:
                    capture_running = False
                    continue
                _log_capture(item)
                append_jsonl(settings.log_dir / "capture-events.jsonl", item.to_record())
                correlator.add_capture_record(item)

            finished = finite and not capture_running
            for event in correlator.flush(force=finished):
                append_jsonl(args.output, event)
                _log_event(event)
                written += 1

            if finished:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            if args.mode == "capture" and backend is not None and not capture_running and not finite:
                log.error("CAPTURE stopped unexpectedly; exiting")
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        log.info("OBSERVER interrupted")
    finally:
        if backend is not None:
            backend.stop()
        for event in correlator.flush(force=True):
            append_jsonl(args.output, event)
            _log_event(event)
            written += 1

    log.info("OBSERVER wrote %d event(s) to %s", written, args.output)
    if args.read_pcap is not None and written == 0:
        log.warning("HINT no HTTP exchange matched filter %r in %s; is the API port different? "
                    "Pass e.g. --filter \"tcp port 8000\"", args.filter, args.read_pcap)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 2
    args = parse_args(settings, argv)
    if args.list_interfaces:
        return _list_interfaces(settings, args.backend or settings.capture_backend)
    return run(settings, args)


if __name__ == "__main__":
    sys.exit(main())
