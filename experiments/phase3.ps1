# Runs the full Phase 3 experiment. Takes about an hour on qwen2.5:7b.

uv run python experiments/run_attack.py --runs 50 --clean-runs 0 --attack direct --defense tagging --label phase3_direct_tagging

foreach ($defense in "none", "allowlist", "tagging", "strict") {
    uv run python experiments/run_attack.py --runs 30 --clean-runs 0 --attack spoof --defense $defense --label "phase3_spoof_$defense"
}

foreach ($defense in "none", "allowlist", "tagging", "strict") {
    uv run python experiments/run_attack.py --runs 0 --clean-runs 20 --task reply --defense $defense --label "phase3_reply_$defense"
}
