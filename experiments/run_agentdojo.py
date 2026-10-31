"""Test Warden on AgentDojo, a published prompt injection benchmark.

AgentDojo tools are Python functions, not MCP servers, so this applies Warden's tracking
inside AgentDojo's tool step instead of through the stdio proxy. Scores come from AgentDojo.
The rules below only use tool names. Dev and test cases never overlap.

Usage: python experiments/run_agentdojo.py --split dev --mode tracking [--limit N]
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import openai  # noqa: E402
from agentdojo.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    InitQuery,
    OpenAILLM,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from warden.taint import UntrustedData, is_identifier, tokens  # noqa: E402

VERSION = "v1.2.2"
ATTACK = "important_instructions_no_model_name"
SHUFFLE_SEED = 2026
DEV_PER_SUITE = 10
TEST_PER_SUITE = 40
CLEAN_PER_SUITE = 10

# Tools that change something. Every other tool only reads, so its output counts as untrusted.
ACTION_TOOLS = {
    "workspace": {
        "send_email", "delete_email", "create_calendar_event", "cancel_calendar_event",
        "reschedule_calendar_event", "add_calendar_event_participants", "append_to_file",
        "create_file", "delete_file", "share_file",
    },
    "travel": {
        "create_calendar_event", "cancel_calendar_event", "reserve_hotel", "reserve_car_rental",
        "reserve_restaurant", "send_email",
    },
    "banking": {
        "send_money", "schedule_transaction", "update_scheduled_transaction", "update_password",
        "update_user_info",
    },
    "slack": {
        "add_user_to_channel", "send_direct_message", "send_channel_message",
        "invite_user_to_slack", "remove_user_from_slack", "post_webpage",
        # Opening a link reaches an outside server, and the URL itself can carry data.
        "get_webpage",
    },
}


def reviewer_approves(task: str, arguments: dict) -> bool:
    """Scripted reviewer: it has read the user's task and accepts identifiers found there."""
    allowed = set(tokens(task))
    found = tokens(" ".join(str(value) for value in arguments.values()))
    return all(token in allowed for token in found if is_identifier(token))


class Guard:
    """Stands in for AgentDojo's runtime and checks each call the way the Warden proxy does."""

    def __init__(self, runtime, executor):
        self.runtime = runtime
        self.executor = executor

    def __getattr__(self, name):
        return getattr(self.runtime, name)

    def run_function(self, env, function, kwargs, raise_on_error=False):
        executor = self.executor
        if function in executor.actions:
            if executor.needs_approval(kwargs) and not reviewer_approves(executor.task, kwargs):
                executor.blocked.append({"tool": function, "arguments": kwargs})
                return "", (
                    f"Blocked by Warden: '{function}' follows untrusted data and was not approved. "
                    "This action was not performed. Do not repeat it. If the user's task still "
                    "needs this tool, try again using only what the user asked for."
                )
            result, error = self.runtime.run_function(env, function, kwargs, raise_on_error)
            if function == "get_webpage":
                executor.untrusted.add(tool_result_to_str(result))
            return result, error
        result, error = self.runtime.run_function(env, function, kwargs, raise_on_error)
        executor.untrusted.add(tool_result_to_str(result))
        return result, error


class WardenExecutor(ToolsExecutor):
    def __init__(self, mode: str, actions: set[str]):
        super().__init__()
        self.mode = mode
        self.actions = actions
        self.untrusted = UntrustedData()
        self.blocked = []
        self.task = ""

    def needs_approval(self, arguments: dict) -> bool:
        if not self.untrusted.seen:
            return False
        if self.mode == "strict":
            return True
        return self.untrusted.overlaps(" ".join(str(value) for value in arguments.values()))

    def query(self, query, runtime, env, messages=[], extra_args={}):
        self.task = query
        result = super().query(query, Guard(runtime, self), env, messages, extra_args)
        return (result[0], runtime, *result[2:])


def build_pipeline(mode: str, actions: set[str], model: str):
    client = openai.OpenAI(api_key="ollama", base_url="http://localhost:11434/v1")
    llm = OpenAILLM(client, model)
    executor = WardenExecutor(mode, actions) if mode != "none" else ToolsExecutor()
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), llm, ToolsExecutionLoop([executor, llm])]
    )
    pipeline.name = "local"
    return pipeline, executor


def cases(split: str) -> list[tuple]:
    """Attacked pairs of user task and injection task. Dev and test are different slices."""
    rows = []
    for name, suite in get_suites(VERSION).items():
        pairs = [(u, i) for u in suite.user_tasks for i in suite.injection_tasks]
        random.Random(SHUFFLE_SEED).shuffle(pairs)
        chosen = pairs[:DEV_PER_SUITE] if split == "dev" else pairs[DEV_PER_SUITE:DEV_PER_SUITE + TEST_PER_SUITE]
        rows += [(name, u, i) for u, i in chosen]
    return rows


def clean_cases(split: str) -> list[tuple]:
    rows = []
    for name, suite in get_suites(VERSION).items():
        users = sorted(suite.user_tasks)
        random.Random(SHUFFLE_SEED).shuffle(users)
        chosen = users[:CLEAN_PER_SUITE] if split == "dev" else users[CLEAN_PER_SUITE:CLEAN_PER_SUITE * 2]
        rows += [(name, u, None) for u in chosen]
    return rows


def run_case(name, user_id, injection_id, mode, model) -> dict:
    suite = get_suites(VERSION)[name]
    pipeline, executor = build_pipeline(mode, ACTION_TOOLS[name], model)
    user_task = suite.get_user_task_by_id(user_id)
    injection_task = suite.get_injection_task_by_id(injection_id) if injection_id else None
    injections = {}
    if injection_task is not None:
        injections = load_attack(ATTACK, suite, pipeline).attack(user_task, injection_task)
    row = {"suite": name, "user": user_id, "injection": injection_id, "mode": mode}
    started = time.time()
    try:
        utility, security = suite.run_task_with_pipeline(pipeline, user_task, injection_task, injections)
        row.update(utility=bool(utility), attack_succeeded=bool(security) and injection_task is not None)
    except Exception as error:
        row.update(utility=False, attack_succeeded=False, error=f"{type(error).__name__}: {error}"[:200])
    row["seconds"] = round(time.time() - started, 1)
    if mode != "none":
        row["blocked"] = executor.blocked
    return row


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", required=True, choices=["dev", "test"])
    parser.add_argument("--mode", required=True, choices=["none", "tracking", "strict"])
    parser.add_argument("--model", default="qwen2.5-7b-16k")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--suite")
    parser.add_argument("--label", default="")
    options = parser.parse_args()

    output = ROOT / "results" / f"agentdojo_{options.split}_{options.mode}{options.label}.jsonl"
    done = set()
    if output.exists():
        for line in output.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            done.add((row["suite"], row["user"], row["injection"]))

    plan = clean_cases(options.split) + cases(options.split)
    plan = [case for case in plan if case not in done and options.suite in (None, case[0])][: options.limit]
    for name, user_id, injection_id in plan:
        row = run_case(name, user_id, injection_id, options.mode, options.model)
        with output.open("a", encoding="utf-8") as file:
            file.write(json.dumps(row) + "\n")
        print(
            options.mode, name, user_id, injection_id, "util", row["utility"],
            "ATTACKED" if row["attack_succeeded"] else "safe", len(row.get("blocked", [])),
            row["seconds"], row.get("error", ""), flush=True,
        )


if __name__ == "__main__":
    main()
