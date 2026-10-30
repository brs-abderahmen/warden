"""First policy: a recipient allowlist for tools that send messages.

The JSON policy file maps a tool name to its rule:
{"send_email": {"recipient_argument": "to", "allowed_domains": ["company.test"]}}
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
    def __init__(self, rules: dict[str, dict]):
        self.rules = rules

    @classmethod
    def load(cls, path: Path) -> "Policy":
        return cls(json.loads(path.read_text(encoding="utf-8")))

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
