"""Argument constraints. Each check returns None when the value passes, or a short reason when it does not.

Checks are deliberately strict: anything that cannot be understood with certainty (an unparsable SQL statement,
an encoded path, a recipient list with a line break) is refused rather than guessed at.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Callable
from email.utils import getaddresses
from typing import Any

import sqlglot
from sqlglot import exp

from .inspect import injection

Check = Callable[[Any, Any], str | None]

CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)] if all(isinstance(v, str) for v in value) else ["\x00non-string"]
    if value is None:
        return []
    return ["\x00non-string"]


def path_under(value: Any, bases: Any) -> str | None:
    """The path must be absolute, plain and inside one of the allowed folders."""
    allowed = [bases] if isinstance(bases, str) else list(bases)
    for path in _strings(value):
        if CONTROL.search(path) or "\x00" in path:
            return "path contains control characters"
        if unicodedata.normalize("NFKC", path) != path:
            return "path contains look-alike Unicode characters"
        if "%" in path:
            return "path contains percent-encoding"
        if "\\" in path:
            return "path contains a backslash"
        if not path.startswith("/"):
            return "path must be absolute"
        parts = path.split("/")
        if any(p in ("..", ".") for p in parts):
            return "path contains a '..' or '.' segment"
        norm = posixpath.normpath(path)
        if not any(norm == b.rstrip("/") or norm.startswith(b.rstrip("/") + "/") for b in allowed):
            return f"path {norm} is outside {', '.join(allowed)}"
    return None


FORBIDDEN_SQL = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.Command,
    exp.Pragma,
    exp.Attach,
    exp.Detach,
    exp.Merge,
    exp.TruncateTable,
)
FORBIDDEN_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "sqlite_compileoption_get"}


def sql_select_only(value: Any, options: Any) -> str | None:
    """Exactly one read-only SELECT statement that touches only allowed tables."""
    if not isinstance(value, str):
        return "sql must be a string"
    tables_allowed: set[str] | None = None
    if isinstance(options, dict) and options.get("tables"):
        tables_allowed = {str(t).lower() for t in options["tables"]}
    try:
        statements = [s for s in sqlglot.parse(value, read="sqlite") if s is not None]
    except sqlglot.errors.ParseError:
        return "sql could not be parsed"
    if len(statements) != 1:
        return "exactly one SQL statement is allowed"
    tree = statements[0]
    if not isinstance(tree, exp.Query):
        return f"only SELECT is allowed (got {tree.key.upper()})"
    for node in tree.walk():
        if isinstance(node, FORBIDDEN_SQL):
            return f"{node.key.upper()} is not allowed"
        if isinstance(node, exp.Anonymous) and str(node.name).lower() in FORBIDDEN_FUNCTIONS:
            return f"function {node.name} is not allowed"
    cte_names = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    for table in tree.find_all(exp.Table):
        name = table.name.lower()
        if name.startswith("sqlite_"):
            return f"system table {name} is not allowed"
        if table.args.get("db") or table.args.get("catalog"):
            return "schema-qualified tables are not allowed"
        if tables_allowed is not None and name not in tables_allowed and name not in cte_names:
            return f"table {name} is not allowed"
    return None


def email_domains(value: Any, domains: Any) -> str | None:
    """Every recipient must be a plain address in an allowed domain. Wildcards like '*.acme.example' allow subdomains."""
    allowed = [domains] if isinstance(domains, str) else [str(d).lower() for d in domains]
    for raw in _strings(value):
        if CONTROL.search(raw):
            return "recipient field contains a line break or control character"
        if unicodedata.normalize("NFKC", raw) != raw or not raw.isascii():
            return "recipient contains non-ASCII characters"
        for _, addr in getaddresses([raw]):
            if not addr:
                continue
            if addr.count("@") != 1 or not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", addr):
                return f"recipient {addr!r} is not a plain email address"
            domain = addr.rsplit("@", 1)[1].lower()
            ok = any(domain == d or (d.startswith("*.") and domain.endswith(d[1:])) for d in allowed)
            if not ok:
                return f"recipient domain {domain} is not allowed"
        if raw.count("@") != len([a for _, a in getaddresses([raw]) if a]):
            return "recipient list could not be parsed unambiguously"
    return None


def max_length(value: Any, limit: Any) -> str | None:
    for s in _strings(value):
        if len(s) > int(limit):
            return f"value longer than {limit} characters"
    return None


def one_of(value: Any, options: Any) -> str | None:
    if value not in list(options):
        return f"value {value!r} is not one of the allowed values"
    return None


def pattern(value: Any, regex: Any) -> str | None:
    for s in _strings(value):
        if not re.fullmatch(str(regex), s):
            return "value does not match the required pattern"
    return None


def deny_pattern(value: Any, regex: Any) -> str | None:
    for s in _strings(value):
        if re.search(str(regex), s, re.I):
            return "value matches a denied pattern"
    return None


def no_injection(value: Any, enabled: Any) -> str | None:
    """Stops an agent from writing prompt-injection text into a shared store (a file, an email, a ticket)."""
    if not enabled:
        return None
    for s in _strings(value):
        verdict = injection.scan(s)
        if verdict.is_injection:
            return f"value looks like a prompt injection ({', '.join(verdict.rules)})"
    return None


CHECKS: dict[str, Check] = {
    "path_under": path_under,
    "sql_select_only": sql_select_only,
    "email_domains": email_domains,
    "max_length": max_length,
    "one_of": one_of,
    "pattern": pattern,
    "deny_pattern": deny_pattern,
    "no_injection": no_injection,
}
