"""Measures the latency the gateway adds and writes eval/latency.md.

1. End to end over stdio: an MCP client calls the sample servers directly (each server a subprocess), then the same
   calls through the gateway (the gateway a subprocess that itself launches the servers). The difference is what an
   agent actually waits for.
2. Inside the gateway: the per-call overhead it records itself (policy, inspection, audit), over the attack suite,
   for rules only and for rules + classifier (classifier time is the network latency recorded when each answer was
   first fetched).
"""

from __future__ import annotations

import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from demo.servers import seed_workspace

from .config import load_policy
from .evaluation import load_suite, overhead_stats, policy_for, run_case
from .inspect.classifier import JevClassifier

CALLS = [
    ("files", "read_file", {"path": "/data/reports/q3-sales-summary.md"}),
    (
        "crm",
        "run_query",
        {"sql": "SELECT p.name, SUM(o.qty) AS units FROM orders o JOIN products p ON p.id = o.product_id GROUP BY p.name"},
    ),
    ("crm", "run_query", {"sql": "SELECT name, email, phone FROM customers LIMIT 20"}),
]


def q(vals: list[float]) -> tuple[float, float]:
    cuts = statistics.quantiles(vals, n=100)
    return statistics.median(vals), cuts[94]


async def _timed(client: Client, name: str, args: dict[str, Any], n: int) -> list[float]:
    out = []
    for _ in range(n):
        t = time.perf_counter()
        await client.call_tool(name, args)
        out.append((time.perf_counter() - t) * 1000)
    return out


async def end_to_end(policy_path: str, n: int) -> dict[str, dict[str, list[float]]]:
    results: dict[str, dict[str, list[float]]] = {}
    with tempfile.TemporaryDirectory(prefix="mcpfw-bench-") as tmp:
        root = Path(tmp) / "ws"
        seed_workspace(root)
        env = {**os.environ, "MCPFW_DEMO_ROOT": str(root), "MCP_FIREWALL_TOKEN": "demo-report-bot-token", "MCP_FIREWALL_OFFLINE": "1"}
        direct = {
            "files": StdioServerParameters(command=sys.executable, args=["-m", "demo.servers.run", "files", "--root", str(root)], env=env),
            "crm": StdioServerParameters(command=sys.executable, args=["-m", "demo.servers.run", "crm"], env=env),
        }
        gateway = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_firewall.cli", "serve", "--policy", policy_path, "--audit", str(Path(tmp) / "audit.jsonl")],
            env=env,
        )
        for server, tool, args in CALLS:
            label = f"{server}.{tool} ({'customer rows, redacted' if 'email' in str(args) else 'report' if server == 'files' else 'aggregate query'})"
            async with Client(direct[server], cache=None) as c:
                await _timed(c, tool, args, 10)  # warm-up
                d = await _timed(c, tool, args, n)
            async with Client(gateway, cache=None) as c:
                await _timed(c, f"{server}__{tool}", args, 10)
                g = await _timed(c, f"{server}__{tool}", args, n)
            results[label] = {"direct": d, "gateway": g}
    return results


async def suite_overhead(policy_path: str) -> dict[str, dict[str, float]]:
    policy = load_policy(policy_path)
    suite = load_suite(Path("eval/suite.jsonl"))
    classifier = JevClassifier(Path("eval/cache/jev.jsonl"))
    rows = []
    for mode in ("rules", "rules+classifier"):
        pol = policy_for(policy, mode)
        for case in suite:
            rows.append(await run_case(case, mode, pol, classifier if mode == "rules+classifier" else None))
    return overhead_stats(rows)


def main(policy_path: str, n: int, out: str) -> None:
    os.environ["MCP_FIREWALL_OFFLINE"] = "1"
    import logging

    for name in ("mcp", "sqlglot", "httpx2"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    e2e = anyio.run(end_to_end, policy_path, n)
    inside = anyio.run(suite_overhead, policy_path)
    lines = [
        "# Added latency",
        "",
        f"Measured on {platform.system()} {platform.release()}, Python {platform.python_version()}, {os.cpu_count()} logical CPUs. "
        f"Command: `mcp-firewall bench --calls {n}`.",
        "",
        "## End to end over stdio",
        "",
        f"{n} calls per row after 10 warm-up calls. Direct: client to sample server. Gateway: client to gateway to sample server "
        "(rules-only inspection, audit log on).",
        "",
        "| Call | Direct p50 | Direct p95 | Through gateway p50 | Through gateway p95 | Added p50 | Added p95 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, r in e2e.items():
        d50, d95 = q(r["direct"])
        g50, g95 = q(r["gateway"])
        lines.append(f"| {label} | {d50:.2f} ms | {d95:.2f} ms | {g50:.2f} ms | {g95:.2f} ms | {g50 - d50:.2f} ms | {g95 - d95:.2f} ms |")
    lines += [
        "",
        "## Inside the gateway, over the attack suite",
        "",
        "Time from receiving a call to returning it, minus the upstream tool and any wait for approval.",
        "",
        "| Inspection | Calls | p50 | p95 |",
        "| --- | --- | --- | --- |",
    ]
    for mode, s in inside.items():
        lines.append(f"| {mode} | {int(s['n'])} | {s['p50']:.2f} ms | {s['p95']:.2f} ms |")
    lines.append("")
    Path(out).write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("\n".join(lines))
