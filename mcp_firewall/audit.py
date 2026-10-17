"""Append-only, hash-chained JSONL audit log.

Every record carries `seq`, `prev` (the hash of the previous record) and `hash` (SHA-256 of the record without its
own hash). Editing or deleting any line breaks the chain, which `mcp-firewall audit verify` reports.
Arguments are stored after redaction and truncation; tool results are stored only as a hash.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        self.records: list[dict[str, Any]] = []  # kept in memory when there is no file (tests, evaluation)
        if self.path and self.path.exists():
            last = None
            with self.path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last:
                rec = json.loads(last)
                self._seq, self._prev = int(rec["seq"]), str(rec["hash"])

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            record: dict[str, Any] = {
                "seq": self._seq + 1,
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "event": event,
                **fields,
                "prev": self._prev,
            }
            record["hash"] = _digest(record)
            line = json.dumps(record, sort_keys=True, ensure_ascii=False)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                    fh.write(line + "\n")
            else:
                self.records.append(record)
            self._seq, self._prev = record["seq"], record["hash"]
            return record


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Checks the whole chain. Returns (ok, records checked, message)."""
    prev, seq, n = GENESIS, 0, 0
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("prev") != prev:
                return False, n, f"line {lineno}: chain broken (prev hash does not match line before)"
            if _digest(rec) != rec.get("hash"):
                return False, n, f"line {lineno}: record was modified (hash mismatch)"
            if rec.get("seq") != seq + 1:
                return False, n, f"line {lineno}: sequence gap"
            prev, seq, n = rec["hash"], rec["seq"], n + 1
    return True, n, f"{n} records, chain intact"
