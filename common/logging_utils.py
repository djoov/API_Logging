"""Console logging and UTC time helpers shared by all components."""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    """UTC ISO-8601 with millisecond precision, e.g. 2026-09-24T10:00:05.123Z."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def get_logger(component: str, level: int = logging.INFO) -> logging.Logger:
    """Logger printing lines like "[10:00:05] REQUEST request_id=... sender=windows".

    The console shows local wall-clock time for readability; JSONL files always use UTC.
    """
    logger = logging.getLogger(f"lab.{component}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S"))
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(level)
    return logger
