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

CREATE TABLE IF NOT EXISTS workspace_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workspace_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    parent_id INTEGER,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES workspace_products(id),
    FOREIGN KEY (parent_id) REFERENCES workspace_categories(id)
);

CREATE TABLE IF NOT EXISTS ui_parameter_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parameter_name TEXT NOT NULL UNIQUE,
    display_label TEXT NOT NULL,
    help_text TEXT NOT NULL DEFAULT '',
    control_type TEXT NOT NULL DEFAULT 'text',
    display_style TEXT NOT NULL DEFAULT 'classic',
    min_value REAL,
    max_value REAL,
    step_value REAL,
    placeholder TEXT NOT NULL DEFAULT '',
    image_url TEXT NOT NULL DEFAULT '',
    value_image_mode TEXT NOT NULL DEFAULT 'none',
    is_required INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ui_parameter_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parameter_name TEXT NOT NULL,
    option_value TEXT NOT NULL,
    option_label TEXT NOT NULL,
    option_order INTEGER NOT NULL DEFAULT 0,
    image_url TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (parameter_name) REFERENCES ui_parameter_configs(parameter_name)
);

CREATE TABLE IF NOT EXISTS workspace_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    subcategory_id INTEGER,
    rule_type TEXT NOT NULL,
    target TEXT,
    expression TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL DEFAULT 0,
    is_editable INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES workspace_products(id),
    FOREIGN KEY (category_id) REFERENCES workspace_categories(id),
    FOREIGN KEY (subcategory_id) REFERENCES workspace_categories(id)
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
        migrate_workspace_schema(conn)
        seed_default_access(conn)
        seed_default_enhancements(conn)
        seed_workspace_defaults(conn)
        migrate_ui_schema(conn)
        seed_default_ui_schema(conn)


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


def migrate_workspace_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_workspace_categories_tree
        ON workspace_categories(product_id, parent_id, position)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_workspace_rules_order
        ON workspace_rules(product_id, category_id, subcategory_id, position)
        """
    )


def seed_workspace_defaults(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT id FROM workspace_products LIMIT 1").fetchone()
    if row is not None:
        return

    cursor = conn.execute(
        "INSERT INTO workspace_products(name, description) VALUES (?, ?)",
        ("Laptop Pro", "Reference product for pricing and compatibility rules."),
    )
    product_id = int(cursor.lastrowid)
    pricing_id = int(
        conn.execute(
            "INSERT INTO workspace_categories(product_id, name, parent_id, position) VALUES (?, ?, NULL, ?)",
            (product_id, "Pricing", 1),
        ).lastrowid
    )
    discounts_id = int(
        conn.execute(
            "INSERT INTO workspace_categories(product_id, name, parent_id, position) VALUES (?, ?, ?, ?)",
            (product_id, "Discounts", pricing_id, 1),
        ).lastrowid
    )
    conn.execute(
        """
        INSERT INTO workspace_rules(product_id, category_id, subcategory_id, rule_type, target, expression, message, position, is_editable)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            product_id,
            pricing_id,
            discounts_id,
            "constraint",
            "",
            "discount <= 0.2",
            "Discounts over 20% require approval",
            1,
            0,
        ),
    )


def migrate_ui_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ui_parameter_options_lookup
        ON ui_parameter_options(parameter_name, option_order)
        """
    )


def seed_default_ui_schema(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT id FROM ui_parameter_configs LIMIT 1").fetchone()
    if row is not None:
        return

    defaults = [
        ("quantity", "Order Quantity", "Units requested by the customer", "slider", "card", 1, 20, 1, "", "", "none", 1),
        ("base_price", "Base Price", "Starting unit price before discounts", "slider", "accent", 50, 500, 10, "", "", "none", 1),
        ("discount", "Discount", "Promotional discount", "radio_boolean", "pill", 0, 1, 0.05, "", "", "none", 0),
        ("region", "Sales Region", "Primary shipping region", "dropdown", "classic", None, None, None, "Select region", "", "value", 1),
    ]
    conn.executemany(
        """
        INSERT INTO ui_parameter_configs(
            parameter_name, display_label, help_text, control_type, display_style,
            min_value, max_value, step_value, placeholder, image_url, value_image_mode, is_required
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        defaults,
    )

    conn.executemany(
        "INSERT INTO ui_parameter_options(parameter_name, option_value, option_label, option_order, image_url) VALUES (?, ?, ?, ?, ?)",
        [
            ("region", "NA", "North America", 1, ""),
            ("region", "EU", "Europe", 2, ""),
            ("region", "APAC", "Asia Pacific", 3, ""),
            ("discount", "0", "No", 1, ""),
            ("discount", "1", "Yes", 2, ""),
        ],
    )



def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)
