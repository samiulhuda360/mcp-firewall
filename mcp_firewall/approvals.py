"""Approval queue for high-risk calls. Fails closed: no answer before the timeout means the call is refused."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import anyio

Outcome = Literal["approved", "denied", "timeout"]


@dataclass
class PendingApproval:
    id: str
    request_id: str
    identity: str
    role: str
    server: str
    tool: str
    args: dict[str, Any]
    reason: str
    created: float = field(default_factory=time.time)
    expires: float = 0.0
    outcome: Outcome | None = None
    decided_by: str | None = None
    note: str = ""
    event: anyio.Event = field(default_factory=anyio.Event, repr=False)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "identity": self.identity,
            "role": self.role,
            "server": self.server,
            "tool": self.tool,
            "args": self.args,
            "reason": self.reason,
            "created": self.created,
            "expires": self.expires,
            "outcome": self.outcome,
            "decided_by": self.decided_by,
        }


class ApprovalQueue:
    def __init__(self, timeout_seconds: float, max_pending: int = 100) -> None:
        self.timeout = timeout_seconds
        self.max_pending = max_pending
        self.items: dict[str, PendingApproval] = {}

    def pending(self) -> list[PendingApproval]:
        return [p for p in self.items.values() if p.outcome is None]

    def recent(self, limit: int = 20) -> list[PendingApproval]:
        done = [p for p in self.items.values() if p.outcome is not None]
        return sorted(done, key=lambda p: p.created, reverse=True)[:limit]

    def create(
        self, *, request_id: str, identity: str, role: str, server: str, tool: str, args: dict[str, Any], reason: str
    ) -> PendingApproval:
        if len(self.pending()) >= self.max_pending:
            raise RuntimeError("approval queue is full")
        item = PendingApproval(secrets.token_hex(4), request_id, identity, role, server, tool, args, reason)
        item.expires = item.created + self.timeout
        self.items[item.id] = item
        return item

    async def wait(self, item: PendingApproval) -> Outcome:
        with anyio.move_on_after(self.timeout):
            await item.event.wait()
        if item.outcome is None:
            item.outcome = "timeout"
        return item.outcome

    def decide(self, approval_id: str, approve: bool, by: str, note: str = "") -> PendingApproval:
        item = self.items.get(approval_id)
        if item is None:
            raise KeyError(approval_id)
        if item.outcome is not None:
            raise ValueError(f"approval {approval_id} is already {item.outcome}")
        item.outcome = "approved" if approve else "denied"
        item.decided_by = by
        item.note = note
        item.event.set()
        return item
