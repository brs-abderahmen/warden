"""Warden proxy: an MCP server to the agent and an MCP client to the real tool server.

Usage: python -m warden.proxy [--pins pins.json] [--policy policy.json]
       [--approvals approvals.json] [--audit audit.jsonl] -- <upstream command> [args...]
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from warden.approval import Approver
from warden.audit import AuditLog
from warden.pinning import Pins, list_all_tools
from warden.policy import Policy
from warden.taint import UntrustedData


def blocked(reason: str) -> types.CallToolResult:
    text = (
        f"Blocked by Warden: {reason}. This action was not performed. "
        "Continue with the rest of the user's task."
    )
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def result_text(result: types.CallToolResult) -> str:
    parts = [block.text for block in result.content if block.type == "text"]
    if result.structured_content is not None:
        parts.append(json.dumps(result.structured_content))
    return "\n".join(parts)


def build_server(
    upstream: ClientSession,
    pins: Pins | None = None,
    policy: Policy | None = None,
    approver: Approver | None = None,
    audit: AuditLog | None = None,
) -> Server:
    """Create the server the agent talks to, backed by an upstream session."""
    untrusted = UntrustedData()

    async def on_list_tools(ctx, params: types.PaginatedRequestParams | None):
        result = await upstream.list_tools(params=params)
        if pins is None:
            return result
        approved = [tool for tool in result.tools if pins.is_approved(tool)]
        return result.model_copy(update={"tools": approved})

    def needs_approval(name: str, arguments: dict) -> bool:
        if name not in policy.approval_tools or not untrusted.seen:
            return False
        if policy.approval_mode == "always":
            return True
        return untrusted.overlaps(" ".join(str(value) for value in arguments.values()))

    async def decide(name: str, arguments: dict) -> tuple[str, str | None]:
        if pins is not None:
            # Re-read the tools on every call: a tool can change mid-session.
            reason = pins.check(name, await list_all_tools(upstream))
            if reason:
                return "blocked", reason
        if policy is None:
            return "allowed", None
        reason = policy.check(name, arguments)
        if reason:
            return "blocked", reason
        if needs_approval(name, arguments):
            if approver is not None and approver.approves(name, arguments):
                return "approved", None
            return "denied", f"'{name}' follows untrusted data and was not approved"
        return "allowed", None

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        arguments = params.arguments or {}
        try:
            decision, reason = await decide(params.name, arguments)
            if audit is not None:
                audit.record(params.name, arguments, decision, reason)
        except Exception as error:
            return blocked(f"safety check failed ({type(error).__name__})")
        if decision in ("blocked", "denied"):
            return blocked(reason)
        result = await upstream.call_tool(params.name, arguments)
        if policy is not None and params.name in policy.untrusted_sources:
            untrusted.add(result_text(result))
        return result

    return Server("warden", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def run_proxy(
    upstream_params: StdioServerParameters,
    pins: Pins | None = None,
    policy: Policy | None = None,
    approver: Approver | None = None,
    audit: AuditLog | None = None,
) -> None:
    async with stdio_client(upstream_params) as (upstream_read, upstream_write):
        async with ClientSession(upstream_read, upstream_write) as upstream:
            await upstream.initialize()
            server = build_server(upstream, pins, policy, approver, audit)
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
    parser.add_argument("--approvals", type=Path)
    parser.add_argument("--audit", type=Path)
    options = parser.parse_args(args[:split])

    pins = Pins.load(options.pins) if options.pins else None
    policy = Policy.load(options.policy) if options.policy else None
    approver = Approver.load(options.approvals) if options.approvals else None
    audit = AuditLog(options.audit) if options.audit else None
    command, *command_args = args[split + 1 :]
    upstream_params = StdioServerParameters(
        command=command, args=command_args, env=dict(os.environ)
    )
    asyncio.run(run_proxy(upstream_params, pins, policy, approver, audit))


if __name__ == "__main__":
    main()
