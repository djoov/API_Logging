"""Central configuration, loaded from environment variables and an optional .env file.

Every component (server, client, observer) reads its settings from here, so IP
addresses, ports and interfaces live in exactly one place: the .env file of each host.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ConfigError(ValueError):
    """Raised when a configuration value is present but invalid."""


def _load_env_file() -> Path | None:
    # ENV_FILE lets you keep several profiles (e.g. config/kali.env) side by side.
    env_file = Path(os.getenv("ENV_FILE", str(PROJECT_ROOT / ".env")))
    if env_file.is_file():
        # override=False: variables already set in the shell take precedence over the file.
        load_dotenv(env_file, override=False)
        return env_file
    return None


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_int(name: str, default: int) -> int:
    raw = _get_str(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _get_float(name: str, default: float) -> float:
    raw = _get_str(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _get_path(name: str) -> Path | None:
    """Optional file path; relative paths are resolved against the project root."""
    raw = _get_str(name)
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else PROJECT_ROOT / path


def parse_peer_names(raw: str) -> dict[str, str]:
    """Parse "192.168.56.1=windows,192.168.56.101=kali" into {ip: name}."""
    peers: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in raw.split(","))):
        if "=" not in item:
            raise ConfigError(f"PEER_NAMES entry {item!r} must look like IP=name")
        ip, name = (piece.strip() for piece in item.split("=", 1))
        if not ip or not name:
            raise ConfigError(f"PEER_NAMES entry {item!r} must look like IP=name")
        peers[ip] = name
    return peers


@dataclass(frozen=True)
class Settings:
    node_name: str
    app_host: str
    app_port: int
    target_scheme: str
    target_host: str
    target_port: int
    request_timeout: float
    request_retries: int
    retry_backoff: float
    default_delay: float
    default_count: int
    simulated_work_ms: float
    log_dir: Path
    capture_backend: str
    capture_interface: str
    capture_filter: str
    tshark_path: str
    peer_names: dict[str, str]
    merge_window_seconds: float
    tls_cert_file: Path | None  # server certificate (enables HTTPS on the server)
    tls_key_file: Path | None
    tls_ca_file: Path | None  # CA the client trusts when TARGET_SCHEME=https
    env_file: Path | None

    @property
    def server_tls(self) -> bool:
        return self.tls_cert_file is not None and self.tls_key_file is not None

    @property
    def target_url(self) -> str | None:
        if not self.target_host:
            return None
        return f"{self.target_scheme}://{self.target_host}:{self.target_port}"


def load_settings() -> Settings:
    env_file = _load_env_file()

    app_port = _get_int("APP_PORT", 8000)
    log_dir = Path(_get_str("LOG_DIR", "logs"))
    if not log_dir.is_absolute():
        log_dir = PROJECT_ROOT / log_dir

    capture_backend = _get_str("CAPTURE_BACKEND", "auto").lower()
    if capture_backend not in {"auto", "tshark", "tcpdump", "none"}:
        raise ConfigError("CAPTURE_BACKEND must be one of: auto, tshark, tcpdump, none")

    return Settings(
        node_name=_get_str("NODE_NAME", "node").lower(),
        app_host=_get_str("APP_HOST", "0.0.0.0"),
        app_port=app_port,
        target_scheme=_get_str("TARGET_SCHEME", "http"),
        target_host=_get_str("TARGET_HOST"),
        target_port=_get_int("TARGET_PORT", 8000),
        request_timeout=_get_float("REQUEST_TIMEOUT_SECONDS", 5.0),
        request_retries=_get_int("REQUEST_RETRIES", 2),
        retry_backoff=_get_float("RETRY_BACKOFF_SECONDS", 1.0),
        default_delay=_get_float("DEFAULT_DELAY_SECONDS", 5.0),
        default_count=_get_int("DEFAULT_REQUEST_COUNT", 5),
        simulated_work_ms=_get_float("SIMULATED_WORK_MS", 0.0),
        log_dir=log_dir,
        capture_backend=capture_backend,
        # OBSERVER_INTERFACE is the documented name; CAPTURE_INTERFACE is accepted as an alias.
        capture_interface=_get_str("OBSERVER_INTERFACE") or _get_str("CAPTURE_INTERFACE"),
        capture_filter=_get_str("CAPTURE_FILTER") or f"tcp port {app_port}",
        tshark_path=_get_str("TSHARK_PATH"),
        peer_names=parse_peer_names(_get_str("PEER_NAMES")),
        merge_window_seconds=_get_float("OBSERVER_MERGE_WINDOW_SECONDS", 2.0),
        tls_cert_file=_get_path("TLS_CERT_FILE"),
        tls_key_file=_get_path("TLS_KEY_FILE"),
        tls_ca_file=_get_path("TLS_CA_FILE"),
        env_file=env_file,
    )
