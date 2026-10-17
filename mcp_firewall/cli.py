"""Command line: serve the gateway, manage tokens and approvals, verify the audit log, evaluate and benchmark."""

from __future__ import annotations

import argparse
import json
import os
import sys

import anyio
import httpx2

from . import audit
from .config import PolicyError, load_policy
from .policy import hash_token, new_token


def _serve(a: argparse.Namespace) -> int:
    from .proxy import serve_http, serve_stdio

    policy = load_policy(a.policy)
    if a.audit:
        import dataclasses

        policy = dataclasses.replace(policy, audit_path=a.audit)
    if a.transport == "http":
        anyio.run(serve_http, policy, a.host, a.port)
    else:
        anyio.run(serve_stdio, policy, os.environ.get("MCP_FIREWALL_TOKEN"), a.admin_port)
    return 0


def _check(a: argparse.Namespace) -> int:
    try:
        policy = load_policy(a.policy)
    except (PolicyError, OSError) as exc:
        print(f"policy error: {exc}")
        return 1
    print(f"ok: {len(policy.servers)} servers, {len(policy.identities)} identities, {len(policy.roles)} roles")
    for name, role in policy.roles.items():
        print(f"  {name}: {len(role.rules)} rules, redacts {', '.join(role.redact) or 'nothing'}")
    return 0


def _new_token(a: argparse.Namespace) -> int:
    token = new_token()
    print(f"token (give this to the agent, store it as a secret): {token}")
    print(f"token_sha256 (put this in the policy):               {hash_token(token)}")
    return 0


def _audit(a: argparse.Namespace) -> int:
    ok, _n, msg = audit.verify(a.path)
    print(("OK " if ok else "TAMPERED ") + msg)
    return 0 if ok else 1


def _approvals(a: argparse.Namespace) -> int:
    token = os.environ.get(a.token_env, "")
    if not token:
        print(f"set {a.token_env} to an approver token")
        return 2
    headers = {"Authorization": f"Bearer {token}"}
    base = a.url.rstrip("/")
    if a.action == "list":
        r = httpx2.get(f"{base}/api/approvals", headers=headers, timeout=10)
        if r.status_code != 200:
            print(f"error {r.status_code}: {r.text}")
            return 1
        data = r.json()
        if not data["pending"]:
            print("nothing waiting")
        for p in data["pending"]:
            print(f"{p['id']}  {p['identity']} -> {p['server']}/{p['tool']}  {json.dumps(p['args'])}")
        return 0
    if not a.id:
        print("give the approval id")
        return 2
    r = httpx2.post(f"{base}/api/approvals/{a.id}", headers=headers, json={"decision": a.action, "note": a.note}, timeout=10)
    print(r.json() if r.status_code == 200 else f"error {r.status_code}: {r.text}")
    return 0 if r.status_code == 200 else 1


def _eval(a: argparse.Namespace) -> int:
    from .evaluation import main as run_eval

    summary = run_eval(a.policy, a.suite, a.out, tuple(a.modes.split(",")))
    for mode, s in summary["modes"].items():
        print(f"{mode:18s} attack success {s['attack_success']}/{s['attacks']}   false blocks {s['false_blocks']}/{s['benign']}")
    print(f"wrote {a.out}/results.md")
    return 0


def _bench(a: argparse.Namespace) -> int:
    from .bench import main as run_bench

    run_bench(a.policy, a.calls, a.out)
    return 0


def _demo(a: argparse.Namespace) -> int:
    from demo.story import main as run_story

    return run_story(a.agent)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-firewall", description="A security gateway between AI agents and their MCP tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the gateway")
    s.add_argument("--policy", required=True)
    s.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8100)
    s.add_argument("--admin-port", type=int, default=0, help="stdio mode: also serve the approvals page and /metrics on this port")
    s.add_argument("--audit", default=None, help="audit log path (overrides the policy)")
    s.set_defaults(fn=_serve)

    c = sub.add_parser("check", help="validate a policy file")
    c.add_argument("policy")
    c.set_defaults(fn=_check)

    t = sub.add_parser("new-token", help="make an agent token and the hash to put in the policy")
    t.set_defaults(fn=_new_token)

    au = sub.add_parser("audit", help="audit log tools")
    au.add_argument("verify", choices=["verify"])
    au.add_argument("path")
    au.set_defaults(fn=_audit)

    p = sub.add_parser("approvals", help="list, approve or deny waiting calls")
    p.add_argument("action", choices=["list", "approve", "deny"])
    p.add_argument("id", nargs="?")
    p.add_argument("--url", default="http://127.0.0.1:8100")
    p.add_argument("--token-env", default="MCPFW_APPROVER_TOKEN")
    p.add_argument("--note", default="")
    p.set_defaults(fn=_approvals)

    e = sub.add_parser("eval", help="run the attack suite")
    e.add_argument("--policy", default="examples/policy.yaml")
    e.add_argument("--suite", default="eval/suite.jsonl")
    e.add_argument("--out", default="eval")
    e.add_argument("--modes", default="none,rules,rules+classifier")
    e.set_defaults(fn=_eval)

    b = sub.add_parser("bench", help="measure the latency the gateway adds")
    b.add_argument("--policy", default="examples/policy.yaml")
    b.add_argument("--calls", type=int, default=300)
    b.add_argument("--out", default="eval/latency.md")
    b.set_defaults(fn=_bench)

    d = sub.add_parser("demo", help="the Acme Outdoor Gear story: an injected document tries to exfiltrate customer data")
    d.add_argument("--agent", choices=["scripted", "gemini"], default="scripted")
    d.set_defaults(fn=_demo)

    a = ap.parse_args(argv)
    return int(a.fn(a))


if __name__ == "__main__":
    sys.exit(main())
