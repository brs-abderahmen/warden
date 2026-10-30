# Warden

A security proxy for AI agents that use MCP tools. Work in progress.

Warden sits between an agent and its tools. It currently has four defenses:

- **Tool pinning:** approve a tool once, and block it if its description or schema changes, even mid-session.
- **Recipient allowlist:** block emails to domains that are not approved.
- **Untrusted data tracking:** remember what untrusted tools returned, and require approval when a later action contains that data. Strict mode requires approval for every such action after untrusted input.
- **Tamper-evident audit log:** each decision is chained by hash to the one before, and arguments are stored only as hashes.

Any error during a safety check blocks the call.

See [WORKFLOW.md](WORKFLOW.md) for the build plan.

## Results so far

Tests on `qwen2.5:7b`, using the same seeds per setup and judged from mock server state. Approval comes from a scripted reviewer that only accepts replies to Maya without the secret.

| Secret leaked | No defense | Allowlist | Tracking | Strict |
|---|---|---|---|---|
| Direct attack, 50 runs | 5 | 1 | 0 | not run |
| Spoofed attack, 30 runs | 1 | 1 | 0 | 0 |

On a normal reply task, 17 of 20 runs sent the email in every setup, with no calls blocked. The other 3 runs wrote the reply as text without calling the tool, with or without Warden.

These are small tests of two attacks on one model, and the attacks rarely succeed on their own, so they are not general rates. Every normal send needed approval under Tracking, because a reply uses an address from the inbox. A real reviewer may be less reliable than the script. Text matching also cannot catch a rewritten secret on its own.

## Run it

Requires [uv](https://docs.astral.sh/uv/). The experiment also needs [Ollama](https://ollama.com/) with `qwen2.5:7b`.

```bash
uv sync
uv run pytest tests -q
uv run python experiments/run_attack.py --runs 50 --clean-runs 0 --defense tagging --label phase3_direct_tagging
uv run python experiments/analyze.py results/phase3_direct_tagging_qwen2.5-7b.json
```

Everything runs locally against a mock email server. No real email is sent.
