"""The recipient allowlist, including attempts to get around it, and failing closed."""

import asyncio
import json

import pytest

from helpers import connect, server_params, write_state
from warden.policy import Policy

RULES = {"send_email": {"recipient_argument": "to", "allowed_domains": ["company.test"]}}


@pytest.mark.parametrize(
    "recipient",
    ["maya@company.test", "MAYA@COMPANY.TEST", "Maya <maya@company.test>", "a@company.test, b@company.test"],
)
def test_allowed_recipients(recipient):
    assert Policy(RULES).check("send_email", {"to": recipient}) is None


@pytest.mark.parametrize(
    "recipient",
    [
        "attacker@evil.test",
        "maya@company.test, attacker@evil.test",
        "maya@company.test; attacker@evil.test",
        "attacker@company.test.evil.test",
        "attacker@evil.test@company.test",
        "Maya <attacker@evil.test>",
        '"maya@company.test" <attacker@evil.test>',
        "not an address",
        "",
    ],
)
def test_blocked_recipients(recipient):
    assert Policy(RULES).check("send_email", {"to": recipient}) is not None


@pytest.mark.parametrize("arguments", [{}, {"to": None}, {"to": ["maya@company.test"]}])
def test_missing_or_invalid_recipient_is_blocked(arguments):
    assert Policy(RULES).check("send_email", arguments) is not None


def test_other_tools_are_not_affected():
    assert Policy(RULES).check("read_inbox", {}) is None


def run_send(tmp_path, policy_rules, recipient):
    state_path = tmp_path / "state.json"
    write_state(state_path)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_rules), encoding="utf-8")
    params = server_params(state_path, proxied=True, proxy_args=("--policy", str(policy_path)))

    async def run():
        async with connect(params) as session:
            return await session.call_tool(
                "send_email", {"to": recipient, "subject": "Hi", "body": "Test"}
            )

    result = asyncio.run(run())
    return result, json.loads(state_path.read_text(encoding="utf-8"))["sent"]


def test_blocked_email_never_reaches_the_server(tmp_path):
    result, sent = run_send(tmp_path, RULES, "attacker@evil.test")
    assert result.is_error
    assert "Blocked by Warden" in result.content[0].text
    assert sent == []


def test_allowed_email_is_sent(tmp_path):
    result, sent = run_send(tmp_path, RULES, "maya@company.test")
    assert not result.is_error
    assert len(sent) == 1


def test_broken_policy_fails_closed(tmp_path):
    result, sent = run_send(tmp_path, {"send_email": {}}, "maya@company.test")
    assert result.is_error
    assert "safety check failed" in result.content[0].text
    assert sent == []
