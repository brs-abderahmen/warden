"""Score a hand-written challenge set.

Usage: python scanner/evaluate_hard.py <run_dir> <examples.jsonl> <output.json>
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warden.scanner import Scanner  # noqa: E402


def main() -> None:
    scanner = Scanner(Path(sys.argv[1]))
    rows = [
        json.loads(line)
        for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
    ]
    for row in rows:
        row["score"] = scanner.score(row["text"])
        row["flagged"] = row["score"] >= scanner.threshold

    poison = [row for row in rows if row["label"] == 1]
    benign = [row for row in rows if row["label"] == 0]
    results = {
        "threshold": scanner.threshold,
        "poison_caught": sum(row["flagged"] for row in poison),
        "poison_total": len(poison),
        "benign_flagged": sum(row["flagged"] for row in benign),
        "benign_total": len(benign),
        "rows": rows,
    }
    Path(sys.argv[3]).write_text(json.dumps(results, indent=2), encoding="utf-8")
    print({key: value for key, value in results.items() if key != "rows"})
    for row in rows:
        if row["flagged"] != (row["label"] == 1):
            print(f"  wrong label={row['label']} score={row['score']:.3f} {row['text'][:80]}")


if __name__ == "__main__":
    main()
