"""Secret and personal-data redaction for tool results.

Each detector finds candidate spans with a pattern, then confirms them where a checksum exists:
credit cards with the Luhn check, New Zealand IRD numbers with the Inland Revenue mod-11 check digit.
Matches are replaced with `[REDACTED:<kind>]`.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

KINDS = ("secret", "card", "ird", "email", "phone")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


IRD_PRIMARY = (3, 2, 7, 6, 5, 4, 3, 2)
IRD_SECONDARY = (7, 4, 3, 2, 5, 2, 7, 6)


def ird_ok(number: str) -> bool:
    """Validates an NZ IRD number (8 or 9 digits) with the Inland Revenue check-digit algorithm."""
    digits = re.sub(r"\D", "", number)
    if len(digits) not in (8, 9):
        return False
    digits = digits.zfill(9)
    value = int(digits)
    if not 10_000_000 < value < 150_000_000:
        return False
    base, check = digits[:8], int(digits[8])
    for weights in (IRD_PRIMARY, IRD_SECONDARY):
        remainder = sum(int(d) * w for d, w in zip(base, weights, strict=True)) % 11
        expected = 0 if remainder == 0 else 11 - remainder
        if expected != 10:
            return expected == check
    return False


SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub token
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),  # Stripe
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),  # sk- style provider keys
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@[^\s]+"),
]
# key = value pairs where the name says it is a secret; only the value is replaced.
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:[a-z0-9_]*?)(?:api[_-]?key|(?:secret|access)[_-]?key|secret|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret))"
    r"(\s*[:=]\s*[\"']?)([^\s\"',;]{8,})"
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
IRD = re.compile(r"\b\d{2,3}[- ]?\d{3}[- ]?\d{3}\b")
IRD_CONTEXT = re.compile(r"(?i)\b(?:ird|tax (?:file )?(?:number|no)|gst)\b")
# NZ numbers: mobiles 02x, landlines 03/04/06/07/09, freephone 0800/0508, in local or +64 form.
PHONE = re.compile(
    r"(?<![\w+])(?:\+64[\s-]?|0)(?:2\d[\s-]?\d{3}[\s-]?\d{3,5}|[34679][\s-]?\d{3}[\s-]?\d{4}|(?:800|508)[\s-]?\d{3}[\s-]?\d{3})(?!\d)"
)


@dataclass
class RedactionResult:
    text: str
    counts: Counter[str]


def _sub(pattern: re.Pattern[str], text: str, kind: str, counts: Counter[str], check: Callable[[re.Match[str]], bool] | None = None) -> str:
    def repl(m: re.Match[str]) -> str:
        if check is not None and not check(m):
            return m.group(0)
        counts[kind] += 1
        return f"[REDACTED:{kind}]"

    return pattern.sub(repl, text)


def redact(text: str, kinds: Iterable[str], keep_email_domains: Iterable[str] = ()) -> RedactionResult:
    """Redacts the requested kinds from text. Secrets go first so that a key never half-matches another rule."""
    wanted = set(kinds)
    counts: Counter[str] = Counter()
    out = text
    if "secret" in wanted:
        for pattern in SECRET_PATTERNS:
            out = _sub(pattern, out, "secret", counts)

        def assign(m: re.Match[str]) -> str:
            if m.group(3).startswith("[REDACTED"):
                return m.group(0)
            counts["secret"] += 1
            return f"{m.group(1)}{m.group(2)}[REDACTED:secret]"

        out = SECRET_ASSIGNMENT.sub(assign, out)
    if "card" in wanted:

        def card_ok(m: re.Match[str]) -> bool:
            digits = re.sub(r"\D", "", m.group(0))
            return 13 <= len(digits) <= 19 and digits[0] in "3456" and luhn_ok(digits)

        out = _sub(CARD, out, "card", counts, card_ok)
    if "ird" in wanted:

        def ird_check(m: re.Match[str]) -> bool:
            formatted = bool(re.fullmatch(r"\d{2,3}-\d{3}-\d{3}", m.group(0)))
            window = m.string[max(0, m.start() - 40) : m.start()]
            return ird_ok(m.group(0)) and (formatted or bool(IRD_CONTEXT.search(window)))

        out = _sub(IRD, out, "ird", counts, ird_check)
    if "email" in wanted:
        keep = {d.lower() for d in keep_email_domains}

        def email_check(m: re.Match[str]) -> bool:
            return m.group(0).rsplit("@", 1)[1].lower() not in keep

        out = _sub(EMAIL, out, "email", counts, email_check)
    if "phone" in wanted:
        out = _sub(PHONE, out, "phone", counts)
    return RedactionResult(out, counts)
