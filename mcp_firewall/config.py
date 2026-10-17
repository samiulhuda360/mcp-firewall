"""The policy file: upstream servers, identities, roles and their rules, inspection, approvals and audit settings."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from .constraints import CHECKS
from .inspect.redact import KINDS

Action = Literal["allow", "deny", "approve"]


class PolicyError(ValueError):
    """The policy file is invalid."""


@dataclass(frozen=True)
class ServerConfig:
    name: str
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    headers_env: dict[str, str] = field(default_factory=dict)  # header name -> env var holding the value


@dataclass(frozen=True)
class Identity:
    id: str
    role: str
    token_sha256: str


@dataclass(frozen=True)
class RateLimit:
    count: int
    seconds: float

    @staticmethod
    def parse(text: str) -> RateLimit:
        m = re.fullmatch(r"\s*(\d+)\s*/\s*(second|minute|hour|day)\s*", text)
        if not m:
            raise PolicyError(f"bad rate limit {text!r}; use e.g. '30/minute'")
        seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}[m.group(2)]
        return RateLimit(int(m.group(1)), float(seconds))


@dataclass(frozen=True)
class Rule:
    server: str
    tools: tuple[str, ...]
    action: Action
    args: dict[str, dict[str, Any]] = field(default_factory=dict)
    rate_limit: RateLimit | None = None
    index: int = 0

    def matches(self, server: str, tool: str) -> bool:
        return fnmatch.fnmatchcase(server, self.server) and any(fnmatch.fnmatchcase(tool, t) for t in self.tools)

    @property
    def label(self) -> str:
        return f"rule[{self.index}] {self.action} {self.server}:{','.join(self.tools)}"


@dataclass(frozen=True)
class Role:
    name: str
    rules: tuple[Rule, ...]
    redact: tuple[str, ...] = ("secret", "card", "ird")
    keep_email_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class InspectionConfig:
    injection: Literal["off", "rules", "rules+classifier"] = "rules"
    on_injection: Literal["block", "flag"] = "block"
    classifier_threshold: float = 0.5
    classifier_cache: str | None = None
    scan_tool_descriptions: bool = True


@dataclass(frozen=True)
class ApprovalConfig:
    timeout_seconds: float = 120.0
    approvers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    servers: dict[str, ServerConfig]
    identities: tuple[Identity, ...]
    roles: dict[str, Role]
    inspection: InspectionConfig = InspectionConfig()
    approvals: ApprovalConfig = ApprovalConfig()
    audit_path: str = "audit.jsonl"
    metrics_public: bool = False
    strict_args: bool = True


def _expand(value: str) -> str:
    return os.path.expandvars(value)


def _need(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d:
        raise PolicyError(f"{where}: missing '{key}'")
    return d[key]


def parse_policy(data: dict[str, Any]) -> Policy:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise PolicyError("policy must be a mapping with 'version: 1'")
    servers: dict[str, ServerConfig] = {}
    for name, s in (data.get("servers") or {}).items():
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise PolicyError(f"server name {name!r} must be lowercase letters, digits and dashes")
        if bool(s.get("command")) == bool(s.get("url")):
            raise PolicyError(f"server {name}: give exactly one of 'command' or 'url'")
        servers[name] = ServerConfig(
            name=name,
            command=_expand(s["command"]) if s.get("command") else None,
            args=tuple(_expand(str(a)) for a in s.get("args", [])),
            env={k: _expand(str(v)) for k, v in (s.get("env") or {}).items()},
            cwd=_expand(s["cwd"]) if s.get("cwd") else None,
            url=s.get("url"),
            headers_env=dict(s.get("headers_env") or {}),
        )
    roles: dict[str, Role] = {}
    for rname, r in (data.get("roles") or {}).items():
        rules: list[Rule] = []
        for i, raw in enumerate(r.get("rules") or []):
            where = f"role {rname} rule {i}"
            action = _need(raw, "action", where)
            if action not in ("allow", "deny", "approve"):
                raise PolicyError(f"{where}: action must be allow, deny or approve")
            server = str(_need(raw, "server", where))
            if "*" not in server and server not in servers:
                raise PolicyError(f"{where}: unknown server {server!r}")
            tools = raw.get("tools", ["*"])
            args = raw.get("args") or {}
            for arg, checks in args.items():
                for check in checks:
                    if check not in CHECKS:
                        raise PolicyError(f"{where}: unknown check {check!r} on argument {arg!r}")
            rl = RateLimit.parse(raw["rate_limit"]) if raw.get("rate_limit") else None
            rules.append(Rule(server, tuple(tools if isinstance(tools, list) else [tools]), action, args, rl, i))
        redact = tuple(r.get("redact", ["secret", "card", "ird"]))
        for kind in redact:
            if kind not in KINDS:
                raise PolicyError(f"role {rname}: unknown redaction kind {kind!r}")
        roles[rname] = Role(rname, tuple(rules), redact, tuple(r.get("keep_email_domains", [])))
    identities: list[Identity] = []
    for raw in data.get("identities") or []:
        role = _need(raw, "role", "identity")
        if role not in roles:
            raise PolicyError(f"identity {raw.get('id')}: unknown role {role!r}")
        digest = str(_need(raw, "token_sha256", f"identity {raw.get('id')}")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PolicyError(f"identity {raw.get('id')}: token_sha256 must be 64 hex characters")
        identities.append(Identity(str(_need(raw, "id", "identity")), role, digest))
    insp = data.get("inspection") or {}
    inspection = InspectionConfig(
        injection=insp.get("injection", "rules"),
        on_injection=insp.get("on_injection", "block"),
        classifier_threshold=float(insp.get("classifier_threshold", 0.5)),
        classifier_cache=insp.get("classifier_cache"),
        scan_tool_descriptions=bool(insp.get("scan_tool_descriptions", True)),
    )
    if inspection.injection not in ("off", "rules", "rules+classifier"):
        raise PolicyError("inspection.injection must be off, rules or rules+classifier")
    appr = data.get("approvals") or {}
    approvals = ApprovalConfig(float(appr.get("timeout_seconds", 120)), tuple(appr.get("approvers", [])))
    known = {i.id for i in identities}
    for a in approvals.approvers:
        if a not in known:
            raise PolicyError(f"approver {a!r} is not a known identity")
    return Policy(
        servers=servers,
        identities=tuple(identities),
        roles=roles,
        inspection=inspection,
        approvals=approvals,
        audit_path=str((data.get("audit") or {}).get("path", "audit.jsonl")),
        metrics_public=bool((data.get("metrics") or {}).get("public", False)),
        strict_args=bool(data.get("strict_args", True)),
    )


def load_policy(path: str | Path) -> Policy:
    with open(path, encoding="utf-8") as fh:
        return parse_policy(yaml.safe_load(fh))
