"""Warden proxy: an MCP server to the agent and an MCP client to the real tool server.

Usage: python -m warden.proxy [--pins pins.json] [--policy policy.json] -- <upstream command> [args...]
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from warden.pinning import Pins, list_all_tools
from warden.policy import Policy


def blocked(reason: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"Blocked by Warden: {reason}")],
        is_error=True,
    )


def build_server(
    upstream: ClientSession, pins: Pins | None = None, policy: Policy | None = None
) -> Server:
    """Create the server the agent talks to, backed by an upstream session."""

    async def on_list_tools(ctx, params: types.PaginatedRequestParams | None):
        result = await upstream.list_tools(params=params)
        if pins is None:
            return result
        approved = [tool for tool in result.tools if pins.is_approved(tool)]
        return result.model_copy(update={"tools": approved})

    async def find_block_reason(name: str, arguments: dict) -> str | None:
        if pins is not None:
            # Re-read the tools on every call: a tool can change mid-session.
            reason = pins.check(name, await list_all_tools(upstream))
            if reason:
                return reason
        return policy.check(name, arguments) if policy is not None else None

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        arguments = params.arguments or {}
        try:
            reason = await find_block_reason(params.name, arguments)
        except Exception as error:
            return blocked(f"safety check failed ({type(error).__name__})")
        if reason:
            return blocked(reason)
        return await upstream.call_tool(params.name, arguments)

    return Server("warden", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def run_proxy(
    upstream_params: StdioServerParameters,
    pins: Pins | None = None,
    policy: Policy | None = None,
) -> None:
    async with stdio_client(upstream_params) as (upstream_read, upstream_write):
        async with ClientSession(upstream_read, upstream_write) as upstream:
            await upstream.initialize()
            server = build_server(upstream, pins, policy)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())


def main() -> None:
    args = sys.argv[1:]
    if "--" not in args or args.index("--") == len(args) - 1:
        sys.exit(__doc__)
    split = args.index("--")

    parser = argparse.ArgumentParser(prog="warden.proxy")
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--policy", type=Path)
    options = parser.parse_args(args[:split])

    pins = Pins.load(options.pins) if options.pins else None
    policy = Policy.load(options.policy) if options.policy else None
    command, *command_args = args[split + 1 :]
    upstream_params = StdioServerParameters(
        command=command, args=command_args, env=dict(os.environ)
    )
    asyncio.run(run_proxy(upstream_params, pins, policy))


if __name__ == "__main__":
    main()
