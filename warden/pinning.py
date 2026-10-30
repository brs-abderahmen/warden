"""Tool pinning: approve a tool once, then block it if it ever changes.

Create pins with: python -m warden.pinning [--scanner run_dir] <pins.json> -- <upstream command> [args...]
"""

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

PINNED_FIELDS = {"name", "title", "description", "input_schema", "output_schema", "annotations"}


def fingerprint(tool: types.Tool) -> str:
    content = tool.model_dump(mode="json", include=PINNED_FIELDS)
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def list_all_tools(session: ClientSession) -> list[types.Tool]:
    tools = []
    params = None
    while True:
        result = await session.list_tools(params=params)
        tools.extend(result.tools)
        if not result.next_cursor:
            return tools
        params = types.PaginatedRequestParams(cursor=result.next_cursor)


class Pins:
    def __init__(self, pins: dict[str, str]):
        self.pins = pins

    @classmethod
    def load(cls, path: Path) -> "Pins":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def is_approved(self, tool: types.Tool) -> bool:
        return self.pins.get(tool.name) == fingerprint(tool)

    def check(self, name: str, tools: list[types.Tool]) -> str | None:
        """Return a reason to block this tool, or None if it matches its pin."""
        if name not in self.pins:
            return f"tool '{name}' has not been approved"
        for tool in tools:
            if tool.name == name:
                if self.is_approved(tool):
                    return None
                return f"tool '{name}' changed since it was approved"
        return f"tool '{name}' is no longer offered by the server"


async def create_pins(upstream_params: StdioServerParameters, path: Path, scanner=None) -> list[str]:
    """Pin the server's tools. Tools the scanner flags are not pinned. Returns their names."""
    async with stdio_client(upstream_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await list_all_tools(session)
    flagged = [
        tool.name
        for tool in tools
        if scanner is not None and scanner.flags(f"{tool.name}: {tool.description or ''}")
    ]
    pins = {tool.name: fingerprint(tool) for tool in tools if tool.name not in flagged}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return flagged


def main() -> None:
    args = sys.argv[1:]
    scanner = None
    if args[:1] == ["--scanner"]:
        from warden.scanner import Scanner

        scanner = Scanner(Path(args[1]))
        args = args[2:]
    if len(args) < 3 or args[1] != "--":
        sys.exit(
            "Usage: python -m warden.pinning [--scanner run_dir] <pins.json> -- <upstream command> [args...]"
        )
    command, *command_args = args[2:]
    upstream_params = StdioServerParameters(
        command=command, args=command_args, env=dict(os.environ)
    )
    flagged = asyncio.run(create_pins(upstream_params, Path(args[0]), scanner))
    if flagged:
        print(f"Not pinned, flagged by the scanner: {', '.join(flagged)}")


if __name__ == "__main__":
    main()
