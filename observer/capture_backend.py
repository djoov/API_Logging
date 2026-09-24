"""Packet-capture backends (TShark, tcpdump) that turn wire traffic into HTTP message records.

What capture can and cannot see (plaintext HTTP only):
  * IP/port/TCP-stream/frame size are always available.
  * Method, URI, status and headers are in the first segment of each message, so they are
    reliable. X-Request-ID travels in a header for exactly this reason.
  * The JSON body may be split across TCP segments. TShark reassembles it; tcpdump does not,
    so with tcpdump the payload must come from the application logs instead.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Literal

from models.schemas import HEADER_RECEIVER, HEADER_REQUEST_ID, HEADER_SENDER


class CaptureError(RuntimeError):
    """Capture tool missing, misconfigured, or failed to start."""


@dataclass
class CaptureRecord:
    kind: Literal["request", "response"]
    timestamp: float  # epoch seconds, as seen by the capture point
    backend: str
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    tcp_stream: int | None = None  # metadata only; keep-alive puts many requests on one stream
    frame_number: int | None = None
    frame_len: int | None = None  # size of the last frame of the message
    message_len: int | None = None  # full (reassembled) HTTP message size when known
    method: str | None = None
    uri: str | None = None
    status_code: int | None = None
    request_in: int | None = None  # frame number of the matching request (TShark only)
    http_time_ms: float | None = None  # TShark's "time since request"
    headers: dict[str, str] = field(default_factory=dict)  # lowercase header names
    body: dict[str, str] = field(default_factory=dict)  # top-level JSON members, if readable

    @property
    def request_id(self) -> str | None:
        return self.headers.get(HEADER_REQUEST_ID.lower()) or self.body.get("request_id")

    @property
    def sender(self) -> str | None:
        return self.headers.get(HEADER_SENDER.lower()) or self.body.get("sender")

    @property
    def receiver(self) -> str | None:
        return self.headers.get(HEADER_RECEIVER.lower()) or self.body.get("receiver")

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["request_id"] = self.request_id
        return record


def _int(value: str) -> int | None:
    value = value.split("|")[0].strip()  # repeated fields (e.g. tunnelled IP) -> take the first
    return int(value) if value.isdigit() else None


def _parse_header_lines(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.split("|"):
        line = line.replace("\\r\\n", "").strip()
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return headers


def _parse_json_members(raw: str) -> dict[str, str]:
    members: dict[str, str] = {}
    for item in filter(None, raw.split("|")):
        if ":" in item:
            key, value = item.split(":", 1)
            members[key] = value
    return members


def _executable(path: str) -> str | None:
    return path if path and Path(path).is_file() else None


class CaptureBackend(ABC):
    name: str = "base"

    def __init__(self, executable: str, interface: str, bpf_filter: str, log: logging.Logger) -> None:
        self.executable = executable
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.log = log
        self._proc: subprocess.Popen[str] | None = None

    @abstractmethod
    def build_command(self) -> list[str]: ...

    @abstractmethod
    def parse_stream(self, lines: Iterable[str]) -> Iterator[CaptureRecord]: ...

    def list_interfaces_command(self) -> list[str]:
        return [self.executable, "-D"]

    def records(self) -> Iterator[CaptureRecord]:
        """Start the capture tool and yield HTTP records until it exits or stop() is called."""
        cmd = self.build_command()
        self.log.info("CAPTURE starting: %s", subprocess.list2cmdline(cmd))
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except OSError as exc:
            raise CaptureError(f"cannot start {self.name}: {exc}") from exc

        threading.Thread(target=self._pump_stderr, daemon=True).start()
        assert self._proc.stdout is not None
        yield from self.parse_stream(self._proc.stdout)

        code = self._proc.wait()
        if code not in (0, None) and not getattr(self, "_stopping", False):
            self.log.error("CAPTURE %s exited with code %s (see messages above)", self.name, code)

    def _pump_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            line = line.strip()
            if line:
                self.log.info("CAPTURE [%s] %s", self.name, line)

    def stop(self) -> None:
        self._stopping = True
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()


class TsharkBackend(CaptureBackend):
    name = "tshark"

    # Order matters: parse_line() unpacks these positionally.
    FIELDS = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "tcp.stream", "frame.len", "tcp.reassembled.length",
        "http.request.method", "http.request.uri", "http.response.code", "http.request_in",
        "http.time", "http.request.line", "http.response.line", "json.member_with_value",
    ]

    def __init__(self, executable: str, interface: str, bpf_filter: str, log: logging.Logger,
                 read_file: Path | None = None) -> None:
        super().__init__(executable, interface, bpf_filter, log)
        self.read_file = read_file

    def build_command(self) -> list[str]:
        if self.read_file:
            source = ["-r", str(self.read_file)]
            if self.bpf_filter:
                # BPF (-f) does not apply to files; the same idea as a display filter:
                port = re.search(r"port\s+(\d+)", self.bpf_filter)
                display = f"http && tcp.port == {port.group(1)}" if port else "http"
            else:
                display = "http"
        else:
            if not self.interface:
                raise CaptureError("no capture interface configured: set OBSERVER_INTERFACE "
                                   "(list them with: python observer/observer.py --list-interfaces)")
            source = ["-i", self.interface, "-f", self.bpf_filter, "-l"]
            display = "http"
        cmd = [self.executable, *source, "-n", "-Y", display, "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n"]
        for name in self.FIELDS:
            cmd += ["-e", name]
        return cmd

    def parse_stream(self, lines: Iterable[str]) -> Iterator[CaptureRecord]:
        for line in lines:
            record = self.parse_line(line)
            if record is not None:
                yield record

    @classmethod
    def parse_line(cls, line: str) -> CaptureRecord | None:
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < len(cls.FIELDS):
            return None
        (frame_no, epoch, ip_src, ip_dst, ip6_src, ip6_dst, sport, dport, stream, frame_len,
         reassembled, method, uri, status, request_in, http_time, req_lines, resp_lines,
         json_members) = parts[: len(cls.FIELDS)]

        if method:
            kind: Literal["request", "response"] = "request"
            headers = _parse_header_lines(req_lines)
        elif status:
            kind = "response"
            headers = _parse_header_lines(resp_lines)
        else:
            return None

        try:
            timestamp = float(epoch)
        except ValueError:
            return None

        return CaptureRecord(
            kind=kind,
            timestamp=timestamp,
            backend=cls.name,
            src_ip=(ip_src or ip6_src).split("|")[0] or None,
            dst_ip=(ip_dst or ip6_dst).split("|")[0] or None,
            src_port=_int(sport),
            dst_port=_int(dport),
            tcp_stream=_int(stream),
            frame_number=_int(frame_no),
            frame_len=_int(frame_len),
            message_len=_int(reassembled) or _int(frame_len),
            method=method.split("|")[0] or None,
            uri=uri.split("|")[0] or None,
            status_code=_int(status),
            request_in=_int(request_in),
            http_time_ms=float(http_time) * 1000 if http_time else None,
            headers=headers,
            body=_parse_json_members(json_members),
        )


class TcpdumpBackend(CaptureBackend):
    """Parses `tcpdump -A` text output. No TCP reassembly: one record per packet that starts
    an HTTP message. Good enough for small lab requests; payload comes from app logs."""

    name = "tcpdump"

    _PACKET_RE = re.compile(
        r"^(?P<ts>\d+\.\d+)\s+IP6?\s+(?P<src>\S+)\.(?P<sport>\d+)\s+>\s+(?P<dst>\S+)\.(?P<dport>\d+):"
        r".*?length\s+(?P<length>\d+)"
    )
    _REQUEST_RE = re.compile(r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\S+) HTTP/1\.[01]")
    _RESPONSE_RE = re.compile(r"HTTP/1\.[01] (\d{3})")
    _HEADER_RE = re.compile(r"^([A-Za-z0-9-]+):\s*(.*)$")

    def build_command(self) -> list[str]:
        if not self.interface:
            raise CaptureError("no capture interface configured: set OBSERVER_INTERFACE "
                               "(list them with: python observer/observer.py --list-interfaces)")
        # -l line-buffered, -nn no name/port resolution, -tt epoch timestamps, -A ASCII payload
        return [self.executable, "-i", self.interface, "-l", "-nn", "-tt", "-s", "0", "-A", *self.bpf_filter.split()]

    def parse_stream(self, lines: Iterable[str]) -> Iterator[CaptureRecord]:
        header_match: re.Match[str] | None = None
        body: list[str] = []
        for line in lines:
            match = self._PACKET_RE.match(line)
            if match:
                if header_match is not None:
                    record = self._to_record(header_match, body)
                    if record is not None:
                        yield record
                header_match, body = match, []
            elif header_match is not None:
                body.append(line.rstrip("\r\n"))
        if header_match is not None:
            record = self._to_record(header_match, body)
            if record is not None:
                yield record

    def _to_record(self, header: re.Match[str], body_lines: list[str]) -> CaptureRecord | None:
        start_index, kind, method, uri, status = None, None, None, None, None
        for index, line in enumerate(body_lines):
            # The first ASCII line also contains the IP/TCP header bytes, so search, don't match.
            req = self._REQUEST_RE.search(line)
            if req:
                start_index, kind, method, uri = index, "request", req.group(1), req.group(2)
                break
            resp = self._RESPONSE_RE.search(line)
            if resp:
                start_index, kind, status = index, "response", int(resp.group(1))
                break
        if kind is None or start_index is None:
            return None

        headers: dict[str, str] = {}
        for line in body_lines[start_index + 1:]:
            if not line.strip():
                break  # blank line ends the header block
            hm = self._HEADER_RE.match(line.strip())
            if hm:
                headers[hm.group(1).lower()] = hm.group(2).strip()

        length = int(header.group("length"))
        return CaptureRecord(
            kind=kind,  # type: ignore[arg-type]
            timestamp=float(header.group("ts")),
            backend=self.name,
            src_ip=header.group("src"),
            src_port=int(header.group("sport")),
            dst_ip=header.group("dst"),
            dst_port=int(header.group("dport")),
            frame_len=length,
            method=method,
            uri=uri,
            status_code=status,
            headers=headers,
        )


def find_tshark(configured: str = "") -> str | None:
    candidates = [configured, shutil.which("tshark") or ""]
    for env_var in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_var)
        if base:
            candidates.append(str(Path(base) / "Wireshark" / "tshark.exe"))
    for candidate in candidates:
        found = _executable(candidate)
        if found:
            return found
    return None


def find_tcpdump() -> str | None:
    return shutil.which("tcpdump")


def create_backend(
    preference: str,
    interface: str,
    bpf_filter: str,
    log: logging.Logger,
    tshark_path: str = "",
    read_file: Path | None = None,
) -> CaptureBackend:
    """Pick a backend. "auto" prefers TShark (it reassembles TCP), then tcpdump."""
    if preference == "none" and read_file is None:
        raise CaptureError("capture disabled by CAPTURE_BACKEND=none")
    if read_file is not None:
        tshark = find_tshark(tshark_path)
        if not tshark:
            raise CaptureError("reading a pcap file needs TShark; install Wireshark/TShark or set TSHARK_PATH")
        return TsharkBackend(tshark, interface, bpf_filter, log, read_file=read_file)

    if preference in ("auto", "tshark"):
        tshark = find_tshark(tshark_path)
        if tshark:
            return TsharkBackend(tshark, interface, bpf_filter, log)
        if preference == "tshark":
            raise CaptureError("TShark not found: install Wireshark (includes TShark) or set TSHARK_PATH")
    if preference in ("auto", "tcpdump"):
        tcpdump = find_tcpdump()
        if tcpdump:
            return TcpdumpBackend(tcpdump, interface, bpf_filter, log)
        if preference == "tcpdump":
            raise CaptureError("tcpdump not found (Kali: sudo apt install tcpdump)")
    raise CaptureError("no capture tool found (TShark or tcpdump); run the observer with --mode app")
