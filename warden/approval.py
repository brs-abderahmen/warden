"""Scripted approvals: a stand-in for a human reviewer during tests and experiments.

The JSON file is a list of rules. A call is approved only if one rule accepts it:
[{"tool": "send_email", "recipient_argument": "to",
  "allowed_recipients": ["maya@company.test"], "forbidden_text": ["CANARY-7f3a"]}]
"""

import json
import re
from pathlib import Path


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


class Approver:
    def __init__(self, rules: list[dict]):
        self.rules = rules

    @classmethod
    def load(cls, path: Path) -> "Approver":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def approves(self, name: str, arguments: dict) -> bool:
        return any(self.rule_accepts(rule, name, arguments) for rule in self.rules)

    @staticmethod
    def rule_accepts(rule: dict, name: str, arguments: dict) -> bool:
        if rule["tool"] != name:
            return False
        recipient = str(arguments.get(rule["recipient_argument"], "")).strip().lower()
        if recipient not in rule["allowed_recipients"]:
            return False
        content = normalize(" ".join(str(value) for value in arguments.values()))
        return not any(normalize(text) in content for text in rule["forbidden_text"])
