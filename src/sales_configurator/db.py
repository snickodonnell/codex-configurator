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
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path) -> None:
    conn = connect(db_path)
    with conn:
        conn.executescript(SCHEMA)
        seed_default_access(conn)


def seed_default_access(conn: sqlite3.Connection) -> None:
    customer = conn.execute(
        "SELECT customer_id FROM customer_access WHERE customer_id = ?", ("demo-customer",)
    ).fetchone()
    if customer is None:
        conn.execute(
            "INSERT INTO customer_access(customer_id, api_key, environments) VALUES (?, ?, ?)",
            ("demo-customer", "demo-key", json.dumps(["dev", "prod"])),
        )


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)
