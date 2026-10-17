"""An in-process demo environment: fresh workspace, the three sample servers, and MCP clients connected to them.

The clients speak the real MCP protocol to the servers through the SDK's in-memory transport, so the evaluation
and the tests exercise the same code paths as a stdio or HTTP deployment, minus the process boundary.
"""

from __future__ import annotations

import tempfile
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from demo.servers import Outbox, SqlState, build_files_server, build_mail_server, build_sql_server, seed_workspace
from mcp_firewall.gateway import McpUpstream


@dataclass
class DemoEnv:
    root: Path
    upstreams: dict[str, Any]
    sql: SqlState
    outbox: Outbox


async def open_env(stack: AsyncExitStack, root: Path | None = None) -> DemoEnv:
    if root is None:
        tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="mcpfw-"))
        root = Path(tmp) / "ws"
    seed_workspace(root)
    files = build_files_server(root)
    crm, sql = build_sql_server()
    mail, outbox = build_mail_server()
    ups: dict[str, Any] = {}
    for name, srv in (("files", files), ("crm", crm), ("mail", mail)):
        up = McpUpstream(srv)
        await up.connect(stack)
        ups[name] = up
    stack.callback(sql.conn.close)
    return DemoEnv(root, ups, sql, outbox)
