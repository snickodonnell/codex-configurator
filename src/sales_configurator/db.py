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

CREATE TABLE IF NOT EXISTS deployment_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    environment TEXT NOT NULL,
    ruleset_id INTEGER NOT NULL,
    action TEXT NOT NULL DEFAULT 'deploy',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ruleset_id) REFERENCES rulesets(id)
);

CREATE TABLE IF NOT EXISTS release_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ruleset_id INTEGER NOT NULL UNIQUE,
    environment TEXT NOT NULL,
    rules_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    requires_ux_update INTEGER NOT NULL DEFAULT 1,
    ux_schema_version INTEGER NOT NULL DEFAULT 0,
    approved_by TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ruleset_id) REFERENCES rulesets(id)
);

CREATE TABLE IF NOT EXISTS ruleset_parameter_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ruleset_id INTEGER NOT NULL,
    parameter_name TEXT NOT NULL,
    data_type TEXT NOT NULL,
    parameter_class TEXT NOT NULL,
    governance_control_types TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ruleset_id) REFERENCES rulesets(id)
);

CREATE TABLE IF NOT EXISTS ui_schema_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ruleset_id INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    change_notes TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
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
    parameter_name TEXT NOT NULL,
    ruleset_id INTEGER NOT NULL,
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
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(parameter_name, ruleset_id),
    FOREIGN KEY (ruleset_id) REFERENCES rulesets(id)
);

CREATE TABLE IF NOT EXISTS ui_parameter_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parameter_name TEXT NOT NULL,
    ruleset_id INTEGER NOT NULL,
    option_value TEXT NOT NULL,
    option_label TEXT NOT NULL,
    option_order INTEGER NOT NULL DEFAULT 0,
    image_url TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (parameter_name, ruleset_id) REFERENCES ui_parameter_configs(parameter_name, ruleset_id)
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

CREATE TABLE IF NOT EXISTS customer_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    project_status TEXT NOT NULL DEFAULT 'draft',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customer_project_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    workspace_product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    configuration_status TEXT NOT NULL DEFAULT 'not_started',
    configuration_state TEXT NOT NULL DEFAULT '{}',
    last_evaluated_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES customer_projects(id),
    FOREIGN KEY (workspace_product_id) REFERENCES workspace_products(id)
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
        migrate_ui_schema(conn)
        migrate_workflow_schema(conn)
        migrate_projects_schema(conn)
        seed_default_access(conn)
        seed_default_enhancements(conn)
        seed_workspace_defaults(conn)


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


def migrate_ui_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ui_parameter_options_lookup
        ON ui_parameter_options(ruleset_id, parameter_name, option_order)
        """
    )


def migrate_workflow_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_release_workflows_lookup
        ON release_workflows(environment, state, requires_ux_update)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ruleset_parameter_profiles_lookup
        ON ruleset_parameter_profiles(ruleset_id, parameter_name)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_deployment_history_env
        ON deployment_history(environment, created_at)
        """
    )


def migrate_projects_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_customer_projects_lookup
        ON customer_projects(customer_id, environment, updated_at)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_customer_project_products_lookup
        ON customer_project_products(project_id, workspace_product_id)
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


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)
