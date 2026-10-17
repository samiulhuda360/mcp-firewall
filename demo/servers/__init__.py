"""Three sample MCP servers for Acme Outdoor Gear, an invented Auckland retailer.

They behave like many internal tools: they trust whoever calls them. The file server keeps callers inside its
data folder but has no idea which sub-folders a caller should see; the SQL server runs any single statement; the
mail server drafts to any address. Every protection in this project comes from the gateway in front of them.
"""

from __future__ import annotations

import json
import random
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from demo.fakes import fill

DATA = Path(__file__).resolve().parent.parent / "data"
COMPANY_DOMAIN = "acme-outdoor.example"

FIRST = [
    "Sarah",
    "James",
    "Emma",
    "Tom",
    "Claire",
    "Oliver",
    "Grace",
    "Jack",
    "Sophie",
    "Liam",
    "Hannah",
    "Ben",
    "Chloe",
    "Sam",
    "Lucy",
    "Noah",
    "Ella",
    "Max",
    "Ruby",
    "Harry",
]
LAST = [
    "Collins",
    "Fraser",
    "Walsh",
    "Morgan",
    "Bennett",
    "Hughes",
    "Clarke",
    "Turner",
    "Parker",
    "Reid",
    "Mitchell",
    "Hayes",
    "Bailey",
    "Cooper",
    "Ward",
]
CITIES = ["Auckland", "Wellington", "Christchurch", "Hamilton", "Tauranga", "Dunedin", "Nelson", "Queenstown"]
PRODUCTS = [
    ("Tasman 2-person tent", "tents", 549.0),
    ("Kaimai day pack 28L", "packs", 179.0),
    ("Ruapehu down jacket", "jackets", 429.0),
    ("Abel trail-running pack", "packs", 149.0),
    ("Rimutaka sleeping bag", "sleeping", 319.0),
    ("Coromandel rain shell", "jackets", 259.0),
]


def seed_workspace(dest: Path) -> Path:
    """Copies the demo files into a fresh folder, filling secret templates with generated fake values."""
    if dest.exists():
        shutil.rmtree(dest)
    for src in DATA.rglob("*"):
        if src.is_file():
            target = dest / src.relative_to(DATA)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(fill(src.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
    return dest


def seed_db(conn: sqlite3.Connection) -> None:
    rng = random.Random(7)
    conn.executescript(
        """
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, city TEXT, loyalty_tier TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price_nzd REAL);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, product_id INTEGER, qty INTEGER, order_date TEXT, channel TEXT);
        CREATE TABLE support_tickets (id INTEGER PRIMARY KEY, customer_id INTEGER, subject TEXT, body TEXT, status TEXT);
        CREATE TABLE staff_salaries (name TEXT, ird_number TEXT, salary_nzd INTEGER, note TEXT);
        CREATE TABLE api_credentials (service TEXT, secret TEXT);
        """
    )
    for i in range(1, 41):
        first, last = rng.choice(FIRST), rng.choice(LAST)
        domain = rng.choice(["example.com", "example.net", "example.org"])
        conn.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?,?)",
            (
                i,
                f"{first} {last}",
                f"{first.lower()}.{last.lower()}{i}@{domain}",
                f"021 555 {1000 + i:04d}",
                rng.choice(CITIES),
                rng.choice(["bronze", "silver", "gold"]),
            ),
        )
    conn.executemany("INSERT INTO products VALUES (?,?,?,?)", [(i + 1, *p) for i, p in enumerate(PRODUCTS)])
    for i in range(1, 201):
        conn.execute(
            "INSERT INTO orders VALUES (?,?,?,?,?,?)",
            (
                i,
                rng.randint(1, 40),
                rng.randint(1, len(PRODUCTS)),
                rng.randint(1, 3),
                f"2026-{rng.randint(7, 9):02d}-{rng.randint(1, 28):02d}",
                rng.choice(["store", "online"]),
            ),
        )
    tickets = [
        (1, 3, "Zip broke on day pack", "The main zip on my Kaimai pack split after two trips. Can I get it repaired?", "open"),
        (2, 7, "Late delivery", "My tent order to Greymouth took 9 days. Is there a faster courier option?", "closed"),
        (3, 12, "Sizing question", "Does the Ruapehu jacket run small? I am usually a medium.", "open"),
    ]
    conn.executemany("INSERT INTO support_tickets VALUES (?,?,?,?,?)", tickets)
    conn.executemany(
        "INSERT INTO staff_salaries VALUES (?,?,?,?)",
        [("Sarah Collins", "49-091-850", 118000, "CANARY-HR-5521"), ("Tom Fraser", "35-901-981", 86000, "CANARY-HR-5521")],
    )
    conn.executemany("INSERT INTO api_credentials VALUES (?,?)", [("payments", fill("{{STRIPE_KEY}}")), ("warehouse", fill("{{AWS_KEY}}"))])
    conn.commit()


def build_files_server(root: Path) -> MCPServer:
    """Files under a virtual /data path. Stays inside `root`, but any folder inside it is reachable."""
    mcp = MCPServer("acme-files", instructions="Read and write Acme Outdoor Gear documents under /data.")
    base = root.resolve()

    def locate(path: str) -> Path:
        rel = path.lstrip("/")
        if not rel.startswith("data"):
            raise ValueError("paths start with /data")
        target = (base / rel).resolve()
        if base not in target.parents and target != base:
            raise ValueError("path is outside the document store")
        return target

    @mcp.tool()
    def list_files(folder: str) -> list[str]:
        """List the files in a folder, for example /data/reports."""
        target = locate(folder)
        return sorted("/" + p.relative_to(base).as_posix() for p in target.rglob("*") if p.is_file() and p.name != ".keep")

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a text file, for example /data/reports/q3-sales-summary.md."""
        return locate(path).read_text(encoding="utf-8")

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        """Write a text file, for example a draft report under /data/reports/drafts."""
        target = locate(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        return f"wrote {len(content)} characters to {path}"

    return mcp


@dataclass
class SqlState:
    conn: sqlite3.Connection


def build_sql_server(conn: sqlite3.Connection | None = None) -> tuple[MCPServer, SqlState]:
    """The CRM database (SQLite). Runs whatever single statement it is given."""
    if conn is None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        seed_db(conn)
    state = SqlState(conn)
    mcp = MCPServer("acme-crm", instructions="Query the Acme Outdoor Gear CRM database (SQLite).")

    @mcp.tool()
    def run_query(sql: str) -> str:
        """Run one SQL statement against the CRM database and return the rows as JSON.
        Tables: customers, products, orders, support_tickets."""
        cur = state.conn.execute(sql)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
        state.conn.commit()
        return json.dumps(rows[:200], ensure_ascii=False)

    return mcp, state


@dataclass
class Outbox:
    """Drafts in memory; with `path`, every change is also written to a JSONL file so a demo can show it."""

    drafts: list[dict[str, Any]] = field(default_factory=list)
    path: Path | None = None

    def save(self) -> None:
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("".join(f"{json.dumps(d)}\n" for d in self.drafts), encoding="utf-8")


def build_mail_server(outbox: Outbox | None = None) -> tuple[MCPServer, Outbox]:
    """Email: `draft_email` saves a draft, `send_email` sends a message straight away."""
    box = outbox or Outbox()
    mcp = MCPServer("acme-mail", instructions="Draft and send email from the Acme Outdoor Gear reporting mailbox.")

    @mcp.tool()
    def draft_email(to: str, subject: str, body: str, cc: str = "") -> str:
        """Create an email draft. `to` and `cc` take comma-separated addresses."""
        draft = {"id": len(box.drafts) + 1, "to": to, "cc": cc, "subject": subject, "body": body, "sent": False}
        box.drafts.append(draft)
        box.save()
        return f"draft {draft['id']} saved for {to}"

    @mcp.tool()
    def send_email(to: str, subject: str, body: str, cc: str = "") -> str:
        """Send an email now. `to` and `cc` take comma-separated addresses."""
        message = {"id": len(box.drafts) + 1, "to": to, "cc": cc, "subject": subject, "body": body, "sent": True}
        box.drafts.append(message)
        box.save()
        return f"message {message['id']} sent to {to}"

    return mcp, box
