"""Mock email MCP server. State lives in a local JSON file; no real email is sent."""

import json
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

STATE_PATH = Path(os.environ["WARDEN_MOCK_STATE"])

mcp = MCPServer("mock-email")


def load_state() -> dict:
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


@mcp.tool()
def read_inbox() -> str:
    """Return every email in the user's inbox as JSON."""
    return json.dumps(load_state()["inbox"], indent=2)


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email from the user's account."""
    state = load_state()
    state["sent"].append({"to": to, "subject": subject, "body": body})
    save_state(state)
    return f"Email sent to {to}"


if __name__ == "__main__":
    mcp.run()
