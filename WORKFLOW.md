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

- [x] Pass-through MCP proxy with no change in behavior
- [x] Tool pinning (SHA-256 of description and schema)
- [x] First policy blocks emails to the attacker's address
- [x] Before-and-after demo recorded: the secret left in 5 of 50 attacked runs without Warden and 1 of 50 with it
- [x] Repo made public
- [ ] Added to CV

Known gap: in seed 5 the agent was blocked, then sent the secret to `it-support@company.test`, the attack email's fake sender on an allowed domain. An allowlist cannot catch this. Phase 3 must.

Known gap: the normal task never sends email, so false blocks are untested. Phase 5 needs normal tasks that do.

## Phase 3: Data tagging and approval

- [x] Tag tool output as untrusted
- [x] Policy engine with JSON rules, on-overlap and strict modes
- [x] Scripted approval step that blocks when no approver is set
- [x] Tamper-evident (hash-chained) audit log
- [x] Seed 5 leak stopped: 0 of 50 direct attacks and 0 of 30 spoofed attacks leaked with tracking
- [ ] Real human approval interface

- [x] Locked test, 20 attacks and 100 runs: 14 leaks without Warden, 14 with the allowlist, 0 with tracking. Tasks passed fell from 99 to 85

Known gap: every normal send needed approval under tracking, because replies reuse addresses from the inbox.

Known gap: after a denied send, the agent usually writes the reply as text instead of sending a clean one. That caused the task losses in the locked test.

## Phase 4: Scanner

- [x] Collect real tool descriptions from public MCP registries
- [x] Generate poisoned examples
- [x] Fine-tune the classifier, splitting train and test by MCP server
- [x] Add the scanner to the proxy (flagged tools are not pinned)
- [x] Hand-written challenge set: 13 of 20 poisons caught, 1 of 20 benign flagged

- [x] Larger, more varied dataset and retrain: 11 of 30 fresh poisons caught, 2 of 30 benign flagged

Known gap: the scanner misses most careful human attacks on the fresh set. Any new threshold must be chosen on validation data and tested on another fresh set.

## Phase 5: Evaluation and release

- [ ] Mock files, calendar and Git servers
- [ ] 150 attacks (50 dev, 100 locked test) and 100 normal tasks
- [ ] Attacks designed to beat Warden
- [ ] Full runs with repeats on 3 models
- [ ] AgentDojo run for comparison with published results
- [ ] Ablation table, security vs utility chart, latency numbers
- [ ] Dashboard, pip package, blog post
