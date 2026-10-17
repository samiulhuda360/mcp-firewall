"""Puts the gateway behind an MCP server: stdio for a locally launched agent, Streamable HTTP for shared use.

Over HTTP every request must carry `Authorization: Bearer <token>`; the token is checked with the SDK's bearer
authentication middleware and mapped to an identity from the policy. Over stdio the identity comes from the
MCP_FIREWALL_TOKEN environment variable given to the gateway process by whoever launches it.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from contextlib import AsyncExitStack
from importlib import resources
from typing import Any

import anyio
import httpx2
import mcp_types as types
import uvicorn
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.stdio import stdio_server
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .approvals import ApprovalQueue
from .audit import AuditLog
from .config import Identity, Policy, ServerConfig
from .gateway import Gateway, McpUpstream, Upstream
from .metrics import Metrics
from .policy import resolve_identity


class PolicyTokenVerifier:
    """Bearer tokens are looked up by SHA-256 hash in the policy's identities."""

    def __init__(self, policy: Policy, metrics: Metrics) -> None:
        self.policy = policy
        self.metrics = metrics

    async def verify_token(self, token: str) -> AccessToken | None:
        ident = resolve_identity(self.policy, token)
        if ident is None:
            self.metrics.inc("mcpfw_auth_failures_total")
            return None
        scopes = [f"role:{ident.role}"] + (["approver"] if ident.id in self.policy.approvals.approvers else [])
        return AccessToken(token="", client_id=ident.id, scopes=scopes)  # the raw token is not kept


def upstream_target(cfg: ServerConfig) -> Any:
    if cfg.command:
        env = {**os.environ, **cfg.env} if cfg.env else None
        # "python" means the interpreter running the gateway, so sample servers start from the same environment.
        command = sys.executable if cfg.command in ("python", "python3") else cfg.command
        return StdioServerParameters(command=command, args=list(cfg.args), env=env, cwd=cfg.cwd)
    headers = {h: os.environ.get(var, "") for h, var in cfg.headers_env.items()}
    assert cfg.url is not None
    return streamable_http_client(cfg.url, http_client=httpx2.AsyncClient(headers=headers, timeout=30))


async def connect_upstreams(policy: Policy, stack: AsyncExitStack) -> dict[str, Upstream]:
    ups: dict[str, Upstream] = {}
    for name, cfg in policy.servers.items():
        up = McpUpstream(upstream_target(cfg))
        await up.connect(stack)
        ups[name] = up
    return ups


def build_mcp_server(gw: Gateway, identity: Callable[[], Identity | None], transport: str) -> Server[Any]:
    def who() -> Identity:
        ident = identity()
        if ident is None:  # the HTTP middleware already refuses unknown callers; this is a second lock
            raise PermissionError("unknown caller")
        return ident

    async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=gw.list_tools(who()))

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        outcome = await gw.call_tool(who(), params.name, params.arguments, transport)
        return outcome.result

    return Server("mcp-firewall", version="1.0.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def http_identity(policy: Policy) -> Callable[[], Identity | None]:
    by_id = {i.id: i for i in policy.identities}

    def get() -> Identity | None:
        tok = get_access_token()
        return by_id.get(tok.client_id) if tok else None

    return get


# ---- admin routes: approvals page and API, metrics, health ----


def _approver(request: Request) -> str | None:
    user = request.user
    if getattr(user, "is_authenticated", False) and "approver" in request.auth.scopes:
        return str(user.display_name)
    return None


def admin_routes(gw: Gateway) -> list[Route]:
    page = resources.files("mcp_firewall").joinpath("web/approvals.html").read_text(encoding="utf-8")

    async def approvals_page(request: Request) -> Response:
        return HTMLResponse(
            page, headers={"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"}
        )

    async def list_approvals(request: Request) -> Response:
        if _approver(request) is None:
            return JSONResponse({"error": "approver token required"}, status_code=401)
        q = gw.approvals
        return JSONResponse(
            {"pending": [p.public() for p in q.pending()], "recent": [p.public() for p in q.recent()], "timeout_seconds": q.timeout}
        )

    async def decide(request: Request) -> Response:
        who = _approver(request)
        if who is None:
            return JSONResponse({"error": "approver token required"}, status_code=401)
        body = await request.json()
        approve = body.get("decision") == "approve"
        try:
            item = gw.approvals.decide(request.path_params["approval_id"], approve, who, str(body.get("note", ""))[:500])
        except KeyError:
            return JSONResponse({"error": "no such approval"}, status_code=404)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        gw.audit.write("approval_decided", approval_id=item.id, request_id=item.request_id, outcome=item.outcome, by=who, note=item.note)
        return JSONResponse(item.public())

    async def metrics(request: Request) -> Response:
        if not gw.policy.metrics_public and _approver(request) is None:
            return PlainTextResponse("approver token required\n", status_code=401)
        return PlainTextResponse(gw.metrics.render(), media_type="text/plain; version=0.0.4")

    async def health(request: Request) -> Response:
        return JSONResponse({"ok": True, "servers": sorted(gw.upstreams), "tools": len(gw.tools), "hidden_tools": len(gw.poisoned)})

    return [
        Route("/approvals", approvals_page),
        Route("/api/approvals", list_approvals),
        Route("/api/approvals/{approval_id}", decide, methods=["POST"]),
        Route("/metrics", metrics),
        Route("/healthz", health),
    ]


def admin_app(gw: Gateway) -> Starlette:
    verifier = PolicyTokenVerifier(gw.policy, gw.metrics)
    return Starlette(routes=admin_routes(gw), middleware=[Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(verifier))])


def http_app(gw: Gateway, host: str, port: int) -> Starlette:
    server = build_mcp_server(gw, http_identity(gw.policy), "http")
    verifier = PolicyTokenVerifier(gw.policy, gw.metrics)
    # The gateway issues no OAuth tokens itself; issuer_url only satisfies the SDK's settings model.
    auth = AuthSettings(issuer_url=AnyHttpUrl(f"http://{host}:{port}"), resource_server_url=None)
    return server.streamable_http_app(host=host, auth=auth, token_verifier=verifier, custom_starlette_routes=admin_routes(gw))


def build_gateway(policy: Policy, upstreams: dict[str, Upstream], audit_path: str | None = None) -> Gateway:
    return Gateway(
        policy,
        upstreams,
        audit=AuditLog(audit_path if audit_path is not None else policy.audit_path),
        metrics=Metrics(),
        approvals=ApprovalQueue(policy.approvals.timeout_seconds),
    )


async def serve_http(policy: Policy, host: str, port: int) -> None:
    async with AsyncExitStack() as stack:
        gw = build_gateway(policy, await connect_upstreams(policy, stack))
        await gw.refresh_tools()
        print(f"mcp-firewall: {len(gw.tools)} tools from {len(gw.upstreams)} servers on http://{host}:{port}/mcp", file=sys.stderr)
        config = uvicorn.Config(http_app(gw, host, port), host=host, port=port, log_level="warning")
        await uvicorn.Server(config).serve()


async def serve_stdio(policy: Policy, token: str | None, admin_port: int = 0) -> None:
    ident = resolve_identity(policy, token)
    if ident is None:
        print("mcp-firewall: MCP_FIREWALL_TOKEN is missing or unknown; refusing to start", file=sys.stderr)
        raise SystemExit(2)
    async with AsyncExitStack() as stack:
        gw = build_gateway(policy, await connect_upstreams(policy, stack))
        await gw.refresh_tools()
        server = build_mcp_server(gw, lambda: ident, "stdio")
        async with anyio.create_task_group() as tg:
            if admin_port:
                config = uvicorn.Config(admin_app(gw), host="127.0.0.1", port=admin_port, log_level="warning")
                tg.start_soon(uvicorn.Server(config).serve)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
            tg.cancel_scope.cancel()


def dump_tools(gw: Gateway, ident: Identity) -> str:
    return json.dumps([t.name for t in gw.list_tools(ident)], indent=2)
