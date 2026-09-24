from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from common.config import Settings, load_settings
from server.api_server import create_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # Tests never write into the real logs/ directory.
    return replace(load_settings(), node_name="kali", log_dir=tmp_path, simulated_work_ms=0.0)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))
