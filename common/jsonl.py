"""Append-only JSONL files (one JSON object per line) and a simple tailer."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

_write_lock = threading.Lock()


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _write_lock, path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


class JsonlTailer:
    """Reads records appended to a JSONL file since the last call.

    Only complete lines (ending in a newline) are returned, so a line that is
    still being written by another process is picked up on the next call.
    """

    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.path = path
        self._offset = 0
        self._buffer = b""
        if not from_start and path.exists():
            self._offset = path.stat().st_size

    def read_new(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        size = self.path.stat().st_size
        if size < self._offset:  # file was truncated or recreated
            self._offset, self._buffer = 0, b""
        if size == self._offset:
            return []
        with self.path.open("rb") as fh:
            fh.seek(self._offset)
            chunk = fh.read(size - self._offset)
        self._offset = size

        data = self._buffer + chunk
        *complete, self._buffer = data.split(b"\n")
        records: list[dict[str, Any]] = []
        for raw in complete:
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                continue  # skip a corrupt line instead of stopping the observer
        return records
