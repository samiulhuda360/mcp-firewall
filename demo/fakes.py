"""Deterministic fake secrets for the demo data and the attack suite.

They are generated at run time from a fixed seed and are never written into the repository, so secret scanners
stay quiet and nothing that looks like a credential is ever published. Templates such as `{{AWS_KEY}}` in demo
files and attack cases are expanded with `fill()`.
"""

from __future__ import annotations

import base64
import random
import re
import string

_rng = random.Random(20261017)
_U = string.ascii_uppercase + string.digits
_A = string.ascii_letters + string.digits


def _s(alphabet: str, n: int) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _jwt_part(obj: str) -> str:
    return base64.urlsafe_b64encode(obj.encode()).decode().rstrip("=")


FAKES: dict[str, str] = {
    "AWS_KEY": "AK" + "IA" + _s(_U, 16),
    "AWS_SECRET": _s(_A + "/+", 40),
    "GITHUB_TOKEN": "gh" + "p_" + _s(_A, 36),
    "STRIPE_KEY": "sk" + "_live_" + _s(_A, 24),
    "SLACK_TOKEN": "xo" + "xb-" + _s(string.digits, 12) + "-" + _s(_A, 24),
    "OPENAI_KEY": "sk" + "-proj-" + _s(_A, 40),
    "GOOGLE_KEY": "AI" + "za" + _s(_A, 35),
    "JWT": _jwt_part('{"alg":"HS256","typ":"JWT"}') + "." + _jwt_part('{"sub":"svc-reporting","role":"admin"}') + "." + _s(_A, 43),
    "DB_URL": "postgres" + "ql://reporting:" + _s(_A, 18) + "@db.internal.acme-outdoor.example:5432/sales",
    "PEM_KEY": "-----BEGIN " + "PRIVATE KEY-----\n" + "\n".join(_s(_A, 64) for _ in range(4)) + "\n-----END " + "PRIVATE KEY-----",
    "SMTP_PASSWORD": _s(_A, 20),
    "WEBHOOK_TOKEN": _s(_A, 32),
}

TEMPLATE = re.compile(r"\{\{([A-Z_]+)\}\}")


def fill(text: str) -> str:
    return TEMPLATE.sub(lambda m: FAKES[m.group(1)], text)


def fill_tree(value: object) -> object:
    if isinstance(value, str):
        return fill(value)
    if isinstance(value, list):
        return [fill_tree(v) for v in value]
    if isinstance(value, dict):
        return {k: fill_tree(v) for k, v in value.items()}
    return value
