"""Policies: a recipient allowlist, plus which tools need approval after untrusted input.

The JSON policy file looks like:
{"rules": {"send_email": {"recipient_argument": "to", "allowed_domains": ["company.test"]}},
 "untrusted_sources": ["read_inbox"],
 "approval_tools": ["send_email"],
 "approval_mode": "on_overlap"}

In "on_overlap" mode, a call needs approval if it contains untrusted data.
In "always" mode, every approval tool needs approval once untrusted data has been read.
"""

import json
import re
from email.utils import getaddresses
from pathlib import Path

ADDRESS = re.compile(r"[^@\s]+@([^@\s]+)")


def recipient_domains(value: str) -> list[str | None]:
    """Return the domain of each recipient, with None for anything unparseable."""
    entries = [entry for entry in re.split(r"[,;]", value) if entry.strip()]
    if not entries:
        return [None]
    domains = []
    for entry in entries:
        parsed = getaddresses([entry], strict=True)
        address = parsed[0][1] if len(parsed) == 1 else ""
        match = ADDRESS.fullmatch(address)
        domains.append(match.group(1).lower() if match else None)
    return domains


class Policy:
    def __init__(
        self,
        rules: dict[str, dict],
        untrusted_sources: tuple[str, ...] = (),
        approval_tools: tuple[str, ...] = (),
        approval_mode: str = "on_overlap",
    ):
        if approval_mode not in ("on_overlap", "always"):
            raise ValueError(f"unknown approval mode: {approval_mode}")
        self.rules = rules
        self.untrusted_sources = untrusted_sources
        self.approval_tools = approval_tools
        self.approval_mode = approval_mode

    @classmethod
    def load(cls, path: Path) -> "Policy":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            data["rules"],
            tuple(data.get("untrusted_sources", ())),
            tuple(data.get("approval_tools", ())),
            data.get("approval_mode", "on_overlap"),
        )

    def check(self, name: str, arguments: dict) -> str | None:
        """Return a reason to block this call, or None if it is allowed."""
        rule = self.rules.get(name)
        if rule is None:
            return None
        allowed = {domain.lower() for domain in rule["allowed_domains"]}
        value = arguments.get(rule["recipient_argument"])
        if not isinstance(value, str):
            return f"'{name}' has no valid recipient"
        for domain in recipient_domains(value):
            if domain not in allowed:
                return f"'{name}' recipient is outside the allowed domains"
        return None
