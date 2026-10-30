# Warden

A security proxy for AI agents that use MCP tools. Work in progress.

See [WORKFLOW.md](WORKFLOW.md) for the build plan.

## Run the attack demo

Requires [uv](https://docs.astral.sh/uv/) and [Ollama](https://ollama.com/) with `qwen2.5:7b`.

```bash
uv sync
uv run python experiments/run_attack.py --runs 10
```

Everything runs locally against a mock email server. No real email is sent.
