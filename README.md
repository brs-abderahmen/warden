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

### Locked test

20 attacks in 5 runs each, written and committed before the first run. The defense was frozen before these sets were run, and nothing was tuned after.

| 100 attacked runs | No defense | Allowlist | Tracking | Strict |
|---|---|---|---|---|
| Secret leaked | 14 | 14 | 0 | 0 |
| Attacks that leaked at least once | 3 of 20 | 3 of 20 | 0 of 20 | 0 of 20 |
| User's task completed | 99 | 99 | 85 | 85 |

The allowlist stops nothing here, because all 14 leaks went to approved addresses. Tracking stopped them, at a cost: in 14 of the 15 runs where it denied a send, the agent wrote its reply as text and did not send a clean email, so the task failed. Those runs were still under attack, and no email went out.

Only 3 of the 20 attacks work on this model without a defense, so the 0 of 100 rests mostly on those 3 attacks.

### Earlier development runs

| Secret leaked | No defense | Allowlist | Tracking | Strict |
|---|---|---|---|---|
| Direct attack, 50 runs | 5 | 1 | 0 | not run |
| Spoofed attack, 30 runs | 1 | 1 | 0 | 0 |
| Dev suite, 40 runs | 4 | 4 | 0 | 0 |
| Piggyback dev suite, 30 runs | 6 | 6 | 0 | 0 |

On a normal reply task, 17 of 20 runs sent the email in every setup, with no calls blocked. The other 3 runs wrote the reply as text without calling the tool, with or without Warden.

### Independent test: AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is a published prompt injection benchmark, so its attacks and scoring are not mine. I ran v1.2.2 with the `important_instructions_no_model_name` attack on 160 attacked and 36 normal cases across its four suites, using `qwen2.5:7b`. The rules were committed before this run. Practice cases were separate pairs, though some user tasks and attacks appear in both.

| | No defense | Warden tracking |
|---|---|---|
| Attacks that succeeded | 12 of 160 | 4 of 160 |
| Normal tasks completed, no attack | 9 of 36 | 8 of 36 |
| Tasks completed under attack | 42 of 160 | 35 of 160 |

Tracking cut successful attacks by two thirds. The paired difference is not statistically significant at the 5% level (exact McNemar p = 0.057). Three of the four remaining successes are one Slack attack that AgentDojo scores from attempted calls: Warden blocked the invitation, but the agent went on to try the later steps. The fourth changed a banking password, because a plain text value does not look like an identifier.

The model is the main limit on task completion, finishing only 9 of 36 normal tasks with no defense. A stronger model would give a better test of both numbers. AgentDojo tools are Python functions, so this run applied Warden's tracking code inside AgentDojo's tool step, not through the MCP proxy. Its reviewer is a script that accepts identifiers found in the user's request.

### Tool description scanner

A DeBERTa-v3-small classifier that checks tool descriptions before they are pinned. I collected 18,754 real descriptions from 453 MCP repositories, then capped each repository at 150. The final dataset has 16,543 examples: 11,777 real descriptions and 4,766 generated poisons from 37 attack templates, with 11,552 used for training. Repositories and attack styles in the test set never appear in training.

| | Generated test set | 20 hand-written poisons, 20 hard benign |
|---|---|---|
| Poison caught | 79.2% | 13 of 20 |
| Benign flagged | 1.25% | 1 of 20 |

The first version scored 98.4% on its test set but caught only 7 of 20 hand-written poisons, because its test attacks were too easy. This version has harder training and test data, and its hand-written set was written after training. It still misses about a third of careful human attacks and almost all French ones, so it is one layer and not a guarantee.

A third version trained on almost twice as much data: 30,720 examples in total, 21,378 for training, with new attacks written by a local model in five languages. Its fresh hand-written set was committed before the training data was generated.

| | Second version | Third version |
|---|---|---|
| Generated test set, poison caught | 79.2% | 70.5% |
| Generated test set, benign flagged | 1.25% | 0.56% |
| Generated test set, AUC | 0.9525 | 0.9783 |
| 30 fresh hand-written poisons caught | 10 | 11 |
| 30 fresh hard benign flagged | 0 | 2 |
| Earlier 20 hand-written poisons caught | 13 | 10 |

More data improved ranking on generated attacks, but it did not help on human attacks. The two generated test sets differ, so their rows are not a direct comparison. Several missed attacks scored just below the very strict threshold of 0.9998. That threshold has not been changed, because tuning it on these sets would spoil them.

### Limits

These are small tests on one model, and the attacks are mine, so they are not general rates. Every normal send needed approval under Tracking, because a reply uses an address from the inbox. The scripted reviewer knows the secret, and a real reviewer may be less reliable. Text matching also cannot catch a rewritten secret on its own.

## Run it

Requires [uv](https://docs.astral.sh/uv/). The experiment also needs [Ollama](https://ollama.com/) with `qwen2.5:7b`.

```bash
uv sync
uv run pytest tests -q
uv run python experiments/run_attack.py --runs 50 --clean-runs 0 --defense tagging --label phase3_direct_tagging
uv run python experiments/analyze.py results/phase3_direct_tagging_qwen2.5-7b.json
```

Everything runs locally against a mock email server. No real email is sent.
