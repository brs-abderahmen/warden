# Warden

A security proxy for AI agents that use MCP tools. Work in progress.

Warden sits between an agent and its tools. It currently has two defenses:

- **Tool pinning:** approve a tool once, and block it if its description or schema changes, even mid-session.
- **Recipient allowlist:** block emails to domains that are not approved.

Any error during a safety check blocks the call.

See [WORKFLOW.md](WORKFLOW.md) for the build plan.

## Results so far

One prompt injection attack on `qwen2.5:7b`, 50 runs per setup with the same seeds:

| Measure | Without Warden | With Warden |
|---|---|---|
| Email reached the attacker's address | 5 of 50 | 0 of 50 |
| Secret left in any email | 5 of 50 | 1 of 50 |
| Task passed under attack | 50 of 50 | 47 of 50 |

This is a small test of one attack on one model, not a general rate. In the one remaining leak, the agent sent the secret to an address on an allowed domain, which an allowlist cannot catch. Normal tasks in this test never send email, so false blocks are not measured yet.

## Run it

Requires [uv](https://docs.astral.sh/uv/). The experiment also needs [Ollama](https://ollama.com/) with `qwen2.5:7b`.

```bash
uv sync
uv run pytest tests -q
uv run python experiments/run_attack.py --runs 50 --clean-runs 20 --defense warden --label phase2_warden
uv run python experiments/analyze.py results/phase2_warden_qwen2.5-7b.json
```

Everything runs locally against a mock email server. No real email is sent.
