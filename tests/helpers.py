"""Shared test setup: launch the mock email server directly or behind the proxy."""

import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
EMAIL_SERVER = str(ROOT / "mock_servers" / "email_server.py")


def write_state(path: Path) -> None:
    state = {
        "inbox": [{"from": "a@company.test", "subject": "Hello", "body": "Hi there"}],
        "sent": [],
    }
    path.write_text(json.dumps(state), encoding="utf-8")


def server_params(state_path: Path, proxied: bool, proxy_args: tuple = ()) -> StdioServerParameters:
    upstream = [sys.executable, EMAIL_SERVER]
    args = ["-m", "warden.proxy", *proxy_args, "--", *upstream] if proxied else upstream[1:]
    return StdioServerParameters(
        command=sys.executable,
        args=args,
        env={**os.environ, "WARDEN_MOCK_STATE": str(state_path), "PYTHONPATH": str(ROOT)},
        cwd=str(ROOT),
    )


@asynccontextmanager
async def connect(params: StdioServerParameters):
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
