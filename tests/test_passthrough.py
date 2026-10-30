"""The proxy must not change normal behavior: same tools, same results, same state."""

import asyncio
import json

from helpers import connect, server_params, write_state


async def exercise(state_path, proxied):
    write_state(state_path)
    async with connect(server_params(state_path, proxied)) as session:
        tools = (await session.list_tools()).tools
        inbox = await session.call_tool("read_inbox", {})
        sent = await session.call_tool(
            "send_email", {"to": "b@company.test", "subject": "Hi", "body": "Test"}
        )
    return {
        "tools": [tool.model_dump() for tool in tools],
        "inbox": inbox.model_dump(),
        "sent": sent.model_dump(),
        "state": json.loads(state_path.read_text(encoding="utf-8")),
    }


def test_proxy_matches_direct_connection(tmp_path):
    direct = asyncio.run(exercise(tmp_path / "direct.json", proxied=False))
    proxied = asyncio.run(exercise(tmp_path / "proxied.json", proxied=True))
    assert proxied == direct


def test_proxy_forwards_write_actions(tmp_path):
    result = asyncio.run(exercise(tmp_path / "state.json", proxied=True))
    assert result["state"]["sent"] == [
        {"to": "b@company.test", "subject": "Hi", "body": "Test"}
    ]
