"""The gateway over real transports: Streamable HTTP (uvicorn on a free local port) and stdio (a subprocess)."""

import socket
import sys
from contextlib import AsyncExitStack, asynccontextmanager

import anyio
import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from demo.env import open_env
from mcp_firewall.proxy import build_gateway, http_app

from .conftest import ROOT

pytestmark = pytest.mark.anyio


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@asynccontextmanager
async def running_gateway(policy, tmp_path):
    async with AsyncExitStack() as stack:
        env = await open_env(stack)
        gw = build_gateway(policy, env.upstreams, audit_path=str(tmp_path / "audit.jsonl"))
        await gw.refresh_tools()
        port = free_port()
        server = uvicorn.Server(uvicorn.Config(http_app(gw, "127.0.0.1", port), host="127.0.0.1", port=port, log_level="error"))
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            while not server.started:
                await anyio.sleep(0.02)
            yield gw, env, f"http://127.0.0.1:{port}"
            server.should_exit = True


def mcp_client(base: str, token: str) -> Client:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30)
    return Client(streamable_http_client(f"{base}/mcp", http_client=http), cache=None)


async def test_http_auth_and_call(policy, tmp_path):
    async with running_gateway(policy, tmp_path) as (gw, _, base):
        async with mcp_client(base, "demo-report-bot-token") as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert "files__read_file" in names
            r = await c.call_tool("files__read_file", {"path": "/data/reports/q3-sales-summary.md"})
            assert "1.84 million" in r.content[0].text
            r = await c.call_tool("files__read_file", {"path": "/data/hr/salaries.csv"})
            assert r.is_error and "refused" in r.content[0].text
        async with httpx2.AsyncClient() as h:
            r = await h.post(
                f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Authorization": "Bearer wrong"}
            )
            assert r.status_code == 401
            r = await h.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert r.status_code == 401
        records = gw.audit.path.read_text(encoding="utf-8")
        assert '"transport": "http"' in records and '"identity": "report-bot"' in records


async def test_http_admin_endpoints_need_an_approver(policy, tmp_path):
    async with running_gateway(policy, tmp_path) as (_, _, base), httpx2.AsyncClient() as h:
        assert (await h.get(f"{base}/metrics")).status_code == 401
        assert (await h.get(f"{base}/metrics", headers={"Authorization": "Bearer wrong"})).status_code == 401
        assert (await h.get(f"{base}/metrics", headers={"Authorization": "Bearer demo-report-bot-token"})).status_code == 401
        ok = await h.get(f"{base}/metrics", headers={"Authorization": "Bearer demo-approver-token"})
        assert ok.status_code == 200 and "mcpfw_auth_failures_total 1" in ok.text
        assert (await h.get(f"{base}/api/approvals", headers={"Authorization": "Bearer demo-support-bot-token"})).status_code == 401
        page = await h.get(f"{base}/approvals")
        assert page.status_code == 200 and "Approver token" in page.text


async def test_http_approval_flow(policy, tmp_path):
    async with running_gateway(policy, tmp_path) as (_, env, base):
        result = {}

        async def agent():
            async with mcp_client(base, "demo-report-bot-token") as c:
                result["r"] = await c.call_tool(
                    "mail__send_email", {"to": "tom.fraser@acme-outdoor.example", "subject": "Q3", "body": "Q3 summary"}
                )

        approver = {"Authorization": "Bearer demo-approver-token"}
        async with anyio.create_task_group() as tg, httpx2.AsyncClient() as h:
            tg.start_soon(agent)
            pending: list = []
            while not pending:
                await anyio.sleep(0.05)
                pending = (await h.get(f"{base}/api/approvals", headers=approver)).json()["pending"]
            assert pending[0]["tool"] == "send_email"
            r = await h.post(f"{base}/api/approvals/{pending[0]['id']}", headers=approver, json={"decision": "approve"})
            assert r.json()["decided_by"] == "sarah"
        assert not result["r"].is_error
        assert env.outbox.drafts[0]["sent"]


async def test_stdio_gateway_subprocess(tmp_path):
    from demo.servers import seed_workspace

    root = tmp_path / "ws"
    seed_workspace(root)
    import os

    env = {**os.environ, "MCPFW_DEMO_ROOT": str(root), "MCP_FIREWALL_TOKEN": "demo-support-bot-token"}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_firewall.cli", "serve", "--policy", str(ROOT / "examples" / "policy.yaml"), "--audit", str(tmp_path / "a.jsonl")],
        env=env,
        cwd=str(ROOT),
    )
    async with Client(params, cache=None) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert "crm__run_query" in names and not any(n.startswith("files__") for n in names)
        r = await c.call_tool("crm__run_query", {"sql": "SELECT COUNT(*) AS n FROM customers"})
        assert '"n": 40' in r.content[0].text
    assert '"transport": "stdio"' in (tmp_path / "a.jsonl").read_text(encoding="utf-8")


def test_stdio_refuses_unknown_token(tmp_path):
    import os
    import subprocess

    env = {**os.environ, "MCP_FIREWALL_TOKEN": "not-a-token", "MCPFW_DEMO_ROOT": str(tmp_path)}
    p = subprocess.run(
        [sys.executable, "-m", "mcp_firewall.cli", "serve", "--policy", str(ROOT / "examples" / "policy.yaml")],
        env=env,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert p.returncode == 2
    assert "refusing to start" in p.stderr
