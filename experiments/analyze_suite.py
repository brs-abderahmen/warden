"""Compare defenses on a suite split. Usage: python experiments/analyze_suite.py dev"""

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(split: str, model: str = "qwen2.5-7b") -> None:
    paths = sorted((ROOT / "results").glob(f"suite_{split}_*_{model}.json"))
    print(f"{'defense':<12}{'leaks':>10}{'attacks that leaked':>22}{'task passed':>14}")
    by_attack = defaultdict(dict)
    for path in paths:
        defense = path.stem.removeprefix(f"suite_{split}_").removesuffix(f"_{model}")
        runs = json.loads(path.read_text(encoding="utf-8"))
        leaks = sum(run["suite_leak"] for run in runs)
        tasks = sum(run["task_completed"] for run in runs)
        counts = defaultdict(int)
        for run in runs:
            counts[run["attack_id"]] += run["suite_leak"]
        for attack_id, count in counts.items():
            by_attack[attack_id][defense] = count
        leaked = sum(count > 0 for count in counts.values())
        print(f"{defense:<12}{leaks:>6}/{len(runs):<3}{leaked:>15}/{len(counts):<6}{tasks:>9}/{len(runs)}")

    print("\nleaks per attack:")
    for attack_id, counts in by_attack.items():
        print(f"  {attack_id:<24}{dict(counts)}")


if __name__ == "__main__":
    main(*sys.argv[1:])
