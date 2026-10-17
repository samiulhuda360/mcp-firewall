"""Runs one sample server over stdio or Streamable HTTP.

python -m demo.servers.run files --root .demo-workspace
python -m demo.servers.run crm
python -m demo.servers.run mail --outbox .demo-workspace/outbox.jsonl
python -m demo.servers.run files --root .demo-workspace --http 8101
"""

from __future__ import annotations

import argparse
from pathlib import Path

from demo.servers import Outbox, build_files_server, build_mail_server, build_sql_server


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("server", choices=["files", "crm", "mail"])
    ap.add_argument("--root", default=".demo-workspace")
    ap.add_argument("--outbox", default=None)
    ap.add_argument("--http", type=int, default=0, help="serve Streamable HTTP on this port instead of stdio")
    a = ap.parse_args()
    if a.server == "files":
        server = build_files_server(Path(a.root))
    elif a.server == "crm":
        server, _ = build_sql_server()
    else:
        server, _ = build_mail_server(Outbox(path=Path(a.outbox) if a.outbox else None))
    if a.http:
        server.run("streamable-http", host="127.0.0.1", port=a.http)
    else:
        server.run()


if __name__ == "__main__":
    main()
