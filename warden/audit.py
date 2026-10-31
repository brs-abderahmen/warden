"""Tamper-evident audit log: each entry includes the hash of the entry before it.

Arguments are stored as a hash so that secrets never end up in the log.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def entry_hash(entry: dict) -> str:
    content = {key: value for key, value in entry.items() if key != "hash"}
    return sha256(json.dumps(content, sort_keys=True, separators=(",", ":")))


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.count = 0
        self.last_hash = GENESIS
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                self.count += 1
                self.last_hash = json.loads(line)["hash"]

    def record(self, tool: str, arguments: dict, decision: str, reason: str | None) -> None:
        entry = {
            "index": self.count,
            "time": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "arguments_sha256": sha256(json.dumps(arguments, sort_keys=True)),
            "decision": decision,
            "reason": reason,
            "previous_hash": self.last_hash,
        }
        entry["hash"] = entry_hash(entry)
        with self.path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(entry) + "\n")
        self.count += 1
        self.last_hash = entry["hash"]


def verify(path: Path) -> bool:
    """Return True if no entry has been changed, removed or reordered."""
    previous = GENESIS
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        entry = json.loads(line)
        if entry["index"] != index or entry["previous_hash"] != previous:
            return False
        if entry_hash(entry) != entry["hash"]:
            return False
        previous = entry["hash"]
    return True
