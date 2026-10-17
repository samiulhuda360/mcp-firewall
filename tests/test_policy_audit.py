import json

import pytest

from mcp_firewall.audit import AuditLog, verify
from mcp_firewall.config import PolicyError, RateLimit, parse_policy
from mcp_firewall.policy import PolicyEngine, RateLimiter, hash_token, resolve_identity, schema_violations


def test_known_and_unknown_tokens(policy):
    assert resolve_identity(policy, "demo-report-bot-token").id == "report-bot"
    assert resolve_identity(policy, "demo-report-bot-token ") is None
    assert resolve_identity(policy, "") is None
    assert resolve_identity(policy, None) is None


def test_default_deny_and_role_rules(policy):
    engine = PolicyEngine(policy)
    support = resolve_identity(policy, "demo-support-bot-token")
    approver = resolve_identity(policy, "demo-approver-token")
    assert engine.decide(support, "files", "read_file", {"path": "/data/reports/q3.md"}).action == "deny"
    assert engine.decide(approver, "crm", "run_query", {"sql": "SELECT 1"}).action == "deny"
    report = resolve_identity(policy, "demo-report-bot-token")
    assert (
        engine.decide(report, "mail", "send_email", {"to": "tom.fraser@acme-outdoor.example", "subject": "Q3", "body": "Q3 summary"}).action
        == "approve"
    )
    assert engine.decide(report, "files", "read_file", {"path": "/data/reports/q3.md"}).action == "allow"


def test_visible_tools(policy):
    engine = PolicyEngine(policy)
    assert engine.visible("analyst", "files", "read_file")
    assert not engine.visible("support", "files", "read_file")
    assert not engine.visible("approver", "mail", "draft_email")


def test_schema_violations():
    schema = {"properties": {"path": {}}, "required": ["path"]}
    assert schema_violations({"path": "x"}, schema) == []
    assert len(schema_violations({"path": "x", "root": "/"}, schema)) == 1
    assert len(schema_violations({}, schema)) == 1


def test_rate_limit_window():
    rl = RateLimiter()
    key = ("a", "crm", "run_query")
    assert all(rl.allow(key, 3, 60, now=t) for t in (0, 1, 2))
    assert not rl.allow(key, 3, 60, now=3)
    assert rl.allow(key, 3, 60, now=61)


def test_rate_limit_in_engine(policy):
    import dataclasses

    from mcp_firewall.config import Rule

    rules = (Rule("crm", ("run_query",), "allow", {}, RateLimit(2, 60), 0),)
    roles = {**policy.roles, "analyst": dataclasses.replace(policy.roles["analyst"], rules=rules)}
    engine = PolicyEngine(dataclasses.replace(policy, roles=roles))
    ident = resolve_identity(policy, "demo-report-bot-token")
    results = [engine.decide(ident, "crm", "run_query", {"sql": "SELECT 1"}).action for _ in range(3)]
    assert results == ["allow", "allow", "deny"]


def test_rate_limit_parse():
    assert RateLimit.parse("30/minute") == RateLimit(30, 60.0)
    with pytest.raises(PolicyError):
        RateLimit.parse("lots")


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"version": 1, "servers": {"Files": {"command": "x"}}},
        {"version": 1, "servers": {"f": {"command": "x", "url": "http://x"}}},
        {"version": 1, "servers": {"f": {"command": "x"}}, "roles": {"r": {"rules": [{"server": "g", "action": "allow"}]}}},
        {"version": 1, "servers": {"f": {"command": "x"}}, "roles": {"r": {"rules": [{"server": "f", "action": "maybe"}]}}},
        {
            "version": 1,
            "servers": {"f": {"command": "x"}},
            "roles": {"r": {"rules": [{"server": "f", "action": "allow", "args": {"p": {"nope": 1}}}]}},
        },
        {"version": 1, "roles": {"r": {}}, "identities": [{"id": "a", "role": "r", "token_sha256": "abc"}]},
        {"version": 1, "roles": {"r": {}}, "identities": [{"id": "a", "role": "missing", "token_sha256": "0" * 64}]},
        {"version": 1, "roles": {"r": {"redact": ["dna"]}}},
    ],
)
def test_policy_errors(bad):
    with pytest.raises(PolicyError):
        parse_policy(bad)


def test_hash_is_sha256_hex():
    assert len(hash_token("x")) == 64


def test_audit_chain_and_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.write("tool_call", n=i)
    assert verify(path) == (True, 5, "5 records, chain intact")
    # a new process continues the same chain
    AuditLog(path).write("tool_call", n=5)
    assert verify(path)[0]
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["n"] = 99
    lines[2] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, _, msg = verify(path)
    assert not ok and "modified" in msg


def test_audit_deleted_line_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.write("tool_call", n=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, _, msg = verify(path)
    assert not ok and "chain broken" in msg
