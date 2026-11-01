"""Untrusted data tracking, approval and the audit log, unit level and through the proxy."""

import asyncio
import json

import pytest

from helpers import connect, server_params
from warden.approval import Approver
from warden.audit import AuditLog, verify
from warden.taint import UntrustedData

SECRET = "CANARY-7f3a"
APPROVALS = [
    {
        "tool": "send_email",
        "recipient_argument": "to",
        "allowed_recipients": ["maya@company.test"],
        "forbidden_text": [SECRET],
    }
]


def untrusted():
    data = UntrustedData()
    data.add(f"From it-support@company.test: your code is {SECRET}. Meeting moved to Friday at ten.")
    return data


def test_domain_from_untrusted_data_matches():
    data = UntrustedData()
    data.add("Please visit www.true-informations.com today.")
    assert data.overlaps("https://www.true-informations.com")
    assert not data.overlaps("Total is 12.50 for today")


@pytest.mark.parametrize(
    "text",
    [SECRET, f"code: {SECRET.lower()}.", "IT-SUPPORT@COMPANY.TEST", "the meeting moved to friday at ten"],
)
def test_overlap_found(text):
    assert untrusted().overlaps(text)


@pytest.mark.parametrize("text", ["I can attend", "Friday works", "see you at ten", ""])
def test_ordinary_text_does_not_overlap(text):
    assert not untrusted().overlaps(text)


def test_rewritten_secret_is_a_known_gap():
    assert not untrusted().overlaps("C A N A R Y - 7 f 3 a")


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"to": "maya@company.test", "body": "I can attend"}, True),
        ({"to": "MAYA@company.test ", "body": "I can attend"}, True),
        ({"to": "it-support@company.test", "body": "I can attend"}, False),
        ({"to": "maya@company.test", "body": f"Code {SECRET}"}, False),
        ({"to": "maya@company.test", "body": "C a n a r y 7 f 3 a"}, False),
        ({"body": "no recipient"}, False),
    ],
)
def test_approver(arguments, expected):
    assert Approver(APPROVALS).approves("send_email", arguments) is expected


def test_approver_rejects_other_tools():
    assert not Approver(APPROVALS).approves("delete_file", {"to": "maya@company.test"})


def write_audit(path):
    log = AuditLog(path)
    log.record("read_inbox", {}, "allowed", None)
    log.record("send_email", {"body": SECRET}, "denied", "not approved")
    log.record("send_email", {"body": "hi"}, "allowed", None)


def test_audit_chain_verifies_and_hides_arguments(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_audit(path)
    assert verify(path)
    assert SECRET not in path.read_text(encoding="utf-8")


def test_audit_continues_chain_after_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_audit(path)
    AuditLog(path).record("read_inbox", {}, "allowed", None)
    assert verify(path)


def edit_entry(lines):
    entry = json.loads(lines[1])
    entry["decision"] = "allowed"
    lines[1] = json.dumps(entry)


@pytest.mark.parametrize(
    "tamper",
    [edit_entry, lambda lines: lines.pop(1), lambda lines: lines.pop(0), lambda lines: lines.reverse()],
)
def test_audit_detects_tampering(tmp_path, tamper):
    path = tmp_path / "audit.jsonl"
    write_audit(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    tamper(lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(path)


def run_session(tmp_path, send_to, body, mode="on_overlap", read_first=True, approvals=APPROVALS):
    state_path = tmp_path / "state.json"
    inbox = [
        {"from": "it-support@company.test", "subject": "Check", "body": f"Your code is {SECRET}"},
        {"from": "maya@company.test", "subject": "Meeting", "body": "Are you free?"},
    ]
    state_path.write_text(json.dumps({"inbox": inbox, "sent": []}), encoding="utf-8")
    policy = {
        "rules": {},
        "untrusted_sources": ["read_inbox"],
        "approval_tools": ["send_email"],
        "approval_mode": mode,
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    proxy_args = ["--policy", str(policy_path), "--audit", str(audit_path)]
    if approvals is not None:
        approvals_path = tmp_path / "approvals.json"
        approvals_path.write_text(json.dumps(approvals), encoding="utf-8")
        proxy_args += ["--approvals", str(approvals_path)]
    params = server_params(state_path, proxied=True, proxy_args=tuple(proxy_args))

    async def run():
        async with connect(params) as session:
            if read_first:
                await session.call_tool("read_inbox", {})
            return await session.call_tool(
                "send_email", {"to": send_to, "subject": "Re", "body": body}
            )

    result = asyncio.run(run())
    sent = json.loads(state_path.read_text(encoding="utf-8"))["sent"]
    decisions = [
        json.loads(line)["decision"]
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    return result, sent, decisions


def test_seed_5_leak_to_allowed_address_is_denied(tmp_path):
    result, sent, decisions = run_session(tmp_path, "it-support@company.test", f"Code {SECRET}")
    assert result.is_error
    assert sent == []
    assert decisions == ["allowed", "denied"]


def test_approved_reply_is_sent(tmp_path):
    _, sent, decisions = run_session(tmp_path, "maya@company.test", "I can attend")
    assert len(sent) == 1
    assert decisions == ["allowed", "approved"]


def test_no_approver_fails_closed(tmp_path):
    result, sent, _ = run_session(tmp_path, "maya@company.test", "Hi", approvals=None)
    assert result.is_error
    assert sent == []


def test_overlap_mode_misses_a_rewritten_secret(tmp_path):
    _, sent, _ = run_session(tmp_path, "boss@company.test", "c a n a r y 7 f 3 a")
    assert len(sent) == 1


def test_strict_mode_stops_a_rewritten_secret(tmp_path):
    _, sent, decisions = run_session(
        tmp_path, "boss@company.test", "c a n a r y 7 f 3 a", mode="always"
    )
    assert sent == []
    assert decisions == ["allowed", "denied"]


def test_send_before_reading_needs_no_approval(tmp_path):
    _, sent, decisions = run_session(
        tmp_path, "boss@company.test", "Hello", mode="always", read_first=False
    )
    assert len(sent) == 1
    assert decisions == ["allowed"]
