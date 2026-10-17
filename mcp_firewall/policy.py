"""Identity lookup and the policy decision for one tool call."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .config import Action, Identity, Policy, Rule
from .constraints import CHECKS


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return "mcpfw_" + secrets.token_urlsafe(32)


def resolve_identity(policy: Policy, token: str | None) -> Identity | None:
    """Maps a bearer token to an identity. Compares hashes in constant time; unknown tokens get None."""
    if not token:
        return None
    digest = hash_token(token)
    found: Identity | None = None
    for ident in policy.identities:
        if hmac.compare_digest(ident.token_sha256, digest):
            found = ident
    return found


class RateLimiter:
    """A sliding-window counter per (identity, server, tool)."""

    def __init__(self) -> None:
        self._events: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: tuple[str, str, str], count: int, seconds: float, now: float | None = None) -> bool:
        t = time.monotonic() if now is None else now
        with self._lock:
            q = self._events[key]
            while q and q[0] <= t - seconds:
                q.popleft()
            if len(q) >= count:
                return False
            q.append(t)
            return True


@dataclass
class Decision:
    action: Action
    reason: str
    rule: str | None = None
    violations: list[str] = field(default_factory=list)


def schema_violations(args: dict[str, Any], schema: dict[str, Any] | None) -> list[str]:
    """Arguments the tool does not declare are refused (a common way to smuggle options past a policy)."""
    if not schema:
        return []
    props = schema.get("properties") or {}
    out = [f"argument {k!r} is not declared by the tool" for k in args if k not in props]
    out += [f"required argument {k!r} is missing" for k in schema.get("required") or [] if k not in args]
    return out


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.limiter = RateLimiter()

    def first_rule(self, role: str, server: str, tool: str) -> Rule | None:
        for rule in self.policy.roles[role].rules:
            if rule.matches(server, tool):
                return rule
        return None

    def visible(self, role: str, server: str, tool: str) -> bool:
        rule = self.first_rule(role, server, tool)
        return rule is not None and rule.action != "deny"

    def decide(self, ident: Identity, server: str, tool: str, args: dict[str, Any], schema: dict[str, Any] | None = None) -> Decision:
        rule = self.first_rule(ident.role, server, tool)
        if rule is None:
            return Decision("deny", f"no rule allows {server}:{tool} for role {ident.role}")
        if rule.action == "deny":
            return Decision("deny", f"{server}:{tool} is denied for role {ident.role}", rule.label)
        violations = schema_violations(args, schema) if self.policy.strict_args else []
        for arg, checks in rule.args.items():
            value = args.get(arg)
            for check, option in checks.items():
                problem = CHECKS[check](value, option)
                if problem:
                    violations.append(f"{arg}: {problem}")
        if violations:
            return Decision("deny", "argument check failed: " + "; ".join(violations), rule.label, violations)
        if rule.rate_limit and not self.limiter.allow((ident.id, server, tool), rule.rate_limit.count, rule.rate_limit.seconds):
            return Decision("deny", f"rate limit {rule.rate_limit.count} per {int(rule.rate_limit.seconds)}s exceeded", rule.label)
        if rule.action == "approve":
            return Decision("approve", "this call needs a person's approval", rule.label)
        return Decision("allow", "allowed", rule.label)
