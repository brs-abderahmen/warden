"""Compare defenses on a suite split.

Usage: python experiments/analyze_suite.py <prefix> <split>, for example: suite_process dev
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(prefix: str, split: str, model: str = "qwen2.5-7b") -> None:
    paths = sorted((ROOT / "results").glob(f"{prefix}_{split}_*_{model}.json"))
    print(f"{'defense':<12}{'leaks':>10}{'attacks leaked':>17}{'task passed':>14}")
    by_attack = defaultdict(dict)
    clean_lines = []
    for path in paths:
        defense = path.stem.removeprefix(f"{prefix}_{split}_").removesuffix(f"_{model}")
        data = json.loads(path.read_text(encoding="utf-8"))
        runs = [run for run in data if run["attack_id"] != "clean"]
        clean = [run for run in data if run["attack_id"] == "clean"]
        leaks = sum(run["suite_leak"] for run in runs)
        tasks = sum(run["task_completed"] for run in runs)
        counts = defaultdict(int)
        for run in runs:
            counts[run["attack_id"]] += run["suite_leak"]
        for attack_id, count in counts.items():
            by_attack[attack_id][defense] = count
        leaked = sum(count > 0 for count in counts.values())
        print(f"{defense:<12}{leaks:>6}/{len(runs):<3}{leaked:>11}/{len(counts):<5}{tasks:>9}/{len(runs)}")
        if clean:
            decisions = Counter(item for run in clean for item in run["decisions"])
            sent = sum(bool(run["emails_sent"]) for run in clean)
            passed = sum(run["task_completed"] for run in clean)
            clean_lines.append(
                f"  {defense:<12}passed {passed}/{len(clean)}, sent email in {sent}, {dict(decisions)}"
            )

    print("\nleaks per attack:")
    for attack_id, counts in by_attack.items():
        print(f"  {attack_id:<24}{dict(counts)}")
    if clean_lines:
        print("\nclean runs:")
        print("\n".join(clean_lines))


if __name__ == "__main__":
    main(*sys.argv[1:])
