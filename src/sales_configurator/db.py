from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS rulesets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_name TEXT NOT NULL DEFAULT 'default-product',
    category TEXT NOT NULL DEFAULT 'general',
    subcategory TEXT NOT NULL DEFAULT 'default',
    version INTEGER NOT NULL DEFAULT 1,
    payload TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    environment TEXT NOT NULL UNIQUE,
    ruleset_id INTEGER NOT NULL,
    deployed_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ruleset_id) REFERENCES rulesets(id)
);

CREATE TABLE IF NOT EXISTS configuration_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    state TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS configuration_memos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    ruleset_id INTEGER,
    product_name TEXT NOT NULL,
    category TEXT NOT NULL,
    subcategory TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    memo TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ruleset_id) REFERENCES rulesets(id)
);

CREATE TABLE IF NOT EXISTS specifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    specification TEXT NOT NULL,
    submitted_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customer_access (
    customer_id TEXT PRIMARY KEY,
    api_key TEXT NOT NULL,
    environments TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS frontend_enhancements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path) -> None:
    conn = connect(db_path)
    with conn:
        conn.executescript(SCHEMA)
        migrate_rulesets_schema(conn)
        migrate_configuration_memo_schema(conn)
        seed_default_access(conn)
        seed_default_enhancements(conn)


def migrate_rulesets_schema(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(rulesets)").fetchall()}
    if "product_name" not in columns:
        conn.execute("ALTER TABLE rulesets ADD COLUMN product_name TEXT NOT NULL DEFAULT 'default-product'")
    if "category" not in columns:
        conn.execute("ALTER TABLE rulesets ADD COLUMN category TEXT NOT NULL DEFAULT 'general'")
    if "subcategory" not in columns:
        conn.execute("ALTER TABLE rulesets ADD COLUMN subcategory TEXT NOT NULL DEFAULT 'default'")
    if "version" not in columns:
        conn.execute("ALTER TABLE rulesets ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_rulesets_versioning
        ON rulesets(environment, product_name, category, subcategory, version)
        """
    )


def seed_default_access(conn: sqlite3.Connection) -> None:
    customer = conn.execute(
        "SELECT customer_id FROM customer_access WHERE customer_id = ?", ("demo-customer",)
    ).fetchone()
    if customer is None:
        conn.execute(
            "INSERT INTO customer_access(customer_id, api_key, environments) VALUES (?, ?, ?)",
            ("demo-customer", "demo-key", json.dumps(["dev", "prod"])),
        )


def migrate_configuration_memo_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_configuration_memos_lookup
        ON configuration_memos(customer_id, environment, product_name, category, subcategory, version)
        """
    )


def seed_default_enhancements(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT id FROM frontend_enhancements LIMIT 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO frontend_enhancements(title, status, notes) VALUES (?, ?, ?)",
            (
                "Configurator Launch Screen",
                "planned",
                "Baseline launch page for admin navigation and portfolio visibility.",
            ),
        )


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)
