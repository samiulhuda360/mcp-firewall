from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("MCP_FIREWALL_OFFLINE", "1")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def policy():
    from mcp_firewall.config import load_policy

    return load_policy(ROOT / "examples" / "policy.yaml")
