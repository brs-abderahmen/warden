"""Pick a looser cut-off on validation data, then test it once on a fresh hand-written set.

Flagging a tool only asks a person to look at it, so a 5% false alarm rate is acceptable here.
Usage: python scanner/choose_cutoff.py <run_dir> <dataset.jsonl> <examples.jsonl> <output.json>
"""

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warden.scanner import Scanner  # noqa: E402

TARGET_FALSE_POSITIVE_RATE = 0.05


def read_rows(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def main() -> None:
    scanner = Scanner(Path(sys.argv[1]))
    val = [row for row in read_rows(sys.argv[2]) if row["split"] == "val"]
    scores = np.array([scanner.score(row["text"]) for row in val])
    labels = np.array([row["label"] for row in val])
    cutoff = float(np.quantile(scores[labels == 0], 1 - TARGET_FALSE_POSITIVE_RATE))

    rows = read_rows(sys.argv[3])
    for row in rows:
        row["score"] = scanner.score(row["text"])
        row["flagged"] = row["score"] >= cutoff
    poison = [row for row in rows if row["label"] == 1]
    benign = [row for row in rows if row["label"] == 0]
    results = {
        "old_threshold": scanner.threshold,
        "cutoff": cutoff,
        "val_poison_caught_pct": float((scores[labels == 1] >= cutoff).mean() * 100),
        "val_benign_flagged_pct": float((scores[labels == 0] >= cutoff).mean() * 100),
        "poison_caught": sum(row["flagged"] for row in poison),
        "poison_total": len(poison),
        "benign_flagged": sum(row["flagged"] for row in benign),
        "benign_total": len(benign),
        "old_poison_caught": sum(row["score"] >= scanner.threshold for row in poison),
        "old_benign_flagged": sum(row["score"] >= scanner.threshold for row in benign),
        "rows": rows,
    }
    Path(sys.argv[4]).write_text(json.dumps(results, indent=2), encoding="utf-8")
    print({key: value for key, value in results.items() if key != "rows"})


if __name__ == "__main__":
    main()
