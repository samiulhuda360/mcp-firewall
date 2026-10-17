"""Prometheus text-format metrics without extra dependencies."""

from __future__ import annotations

import threading
from collections import defaultdict

BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def _labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{v.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"' for k, v in labels)
    return "{" + inner + "}"


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(dict)
        self.hist: dict[str, dict[tuple[tuple[str, str], ...], list[float]]] = defaultdict(dict)
        self.help: dict[str, str] = {
            "mcpfw_requests_total": "Tool calls by final decision.",
            "mcpfw_redactions_total": "Values redacted from tool results, by kind.",
            "mcpfw_injections_total": "Tool results withheld or flagged as prompt injection, by detection layer.",
            "mcpfw_approvals_total": "Approval requests by outcome.",
            "mcpfw_auth_failures_total": "Requests refused because the caller was unknown.",
            "mcpfw_overhead_seconds": "Time the gateway adds to a call (policy, inspection, audit), excluding the upstream tool and waiting for approval.",
            "mcpfw_upstream_seconds": "Time spent in the upstream MCP server.",
        }

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            self.counters[name][key] = self.counters[name].get(key, 0.0) + value

    def observe(self, name: str, seconds: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            h = self.hist[name].setdefault(key, [0.0] * (len(BUCKETS) + 2))
            for i, b in enumerate(BUCKETS):
                if seconds <= b:
                    h[i] += 1
            h[-2] += 1  # count
            h[-1] += seconds  # sum

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for name, series in sorted(self.counters.items()):
                lines += [f"# HELP {name} {self.help.get(name, name)}", f"# TYPE {name} counter"]
                lines += [f"{name}{_labels(k)} {v:g}" for k, v in sorted(series.items())]
            for name, hseries in sorted(self.hist.items()):
                lines += [f"# HELP {name} {self.help.get(name, name)}", f"# TYPE {name} histogram"]
                for k, h in sorted(hseries.items()):
                    for i, b in enumerate(BUCKETS):
                        lines.append(f"{name}_bucket{_labels((*k, ('le', f'{b:g}')))} {h[i]:g}")
                    lines.append(f"{name}_bucket{_labels((*k, ('le', '+Inf')))} {h[-2]:g}")
                    lines.append(f"{name}_count{_labels(k)} {h[-2]:g}")
                    lines.append(f"{name}_sum{_labels(k)} {h[-1]:.6f}")
        return "\n".join(lines) + "\n"
