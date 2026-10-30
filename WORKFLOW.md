# Warden workflow

Warden is a security proxy that sits between an AI agent and its MCP tools.
Nightshift, the on-call agent project, comes after Warden and uses it for safe actions.

## How we work

1. Pick the next unchecked item below.
2. Write the test or success check first.
3. Build the smallest version that passes it.
4. Record real results in `results/`. Never estimate a number.
5. Update this file, then commit.

## Rules

- Only attack the mock servers in this repo. Never test on real services or other people's systems.
- Judge results from mock server state, not from what the agent says.
- Keep a locked test set. Tune on the dev attacks, and run the test attacks only at the end.
- Report the attacks Warden misses as well as the ones it stops.
- Never commit API keys. Keep them in `.env`.

## Phase 1: Attack demo

- [x] Mock email MCP server
- [x] Simple local agent (qwen2.5:7b through Ollama)
- [x] Normal task works
- [x] Planted attack and automatic state check
- [x] Baseline attack success rate in `results/`: 1 of 10 runs on qwen2.5:7b. Ten runs is too few to treat as a precise rate.

## Phase 2: Proxy and first defense

- [ ] Pass-through MCP proxy with no change in behavior
- [ ] Tool pinning (SHA-256 of description and schema)
- [ ] First policy blocks the Phase 1 attack
- [ ] Before-and-after demo recorded
- [ ] Repo made public and added to CV

## Phase 3: Data tagging and approval

- [ ] Tag tool output as untrusted
- [ ] Policy engine with YAML rules
- [ ] Human approval step
- [ ] Tamper-evident (hash-chained) audit log

## Phase 4: Scanner

- [ ] Collect real tool descriptions from public MCP registries
- [ ] Generate poisoned examples
- [ ] Fine-tune the classifier, splitting train and test by MCP server
- [ ] Add the scanner to the proxy

## Phase 5: Evaluation and release

- [ ] Mock files, calendar and Git servers
- [ ] 150 attacks (50 dev, 100 locked test) and 100 normal tasks
- [ ] Attacks designed to beat Warden
- [ ] Full runs with repeats on 3 models
- [ ] AgentDojo run for comparison with published results
- [ ] Ablation table, security vs utility chart, latency numbers
- [ ] Dashboard, pip package, blog post
