from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

from .db import connect, init_db, json_dumps
from .rules_engine import evaluate_rules, normalize_ruleset, optimize_configuration


DEFAULT_RULESET = {
    "constraints": [
        {"expression": "quantity >= 1", "message": "Quantity must be at least 1."},
        {
            "expression": "(region != 'EU') or (discount <= 0.2)",
            "message": "EU discount cannot exceed 20%.",
        },
    ],
    "calculations": [
        {"name": "unit_price", "formula": "base_price * (1 - discount)"},
        {"name": "total_price", "formula": "unit_price * quantity"},
    ],
}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"


def _db_path(app: Flask) -> Path:
    return Path(app.config["DATABASE_PATH"])


def _load_deployed_rules(conn: Any, environment: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT r.payload
        FROM deployments d
        JOIN rulesets r ON d.ruleset_id = r.id
        WHERE d.environment = ?
        """,
        (environment,),
    ).fetchone()
    return normalize_ruleset(json.loads(row["payload"]) if row else DEFAULT_RULESET)


def _authorize(conn: Any, customer_id: str, api_key: str, environment: str) -> bool:
    row = conn.execute(
        "SELECT api_key, environments FROM customer_access WHERE customer_id = ?", (customer_id,)
    ).fetchone()
    if not row or row["api_key"] != api_key:
        return False
    environments = json.loads(row["environments"])
    return environment in environments


def _is_logged_in() -> bool:
    return session.get("username") == ADMIN_USERNAME and session.get("role") == "admin"


def _configure_auth(app: Flask) -> None:
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-change-me")

    @app.before_request
    def require_login() -> Any:
        if request.endpoint in {"login", "static"}:
            return None
        if _is_logged_in():
            return None
        if request.path.startswith("/api/") or request.path == "/optimize":
            return jsonify({"error": "authentication required"}), 401
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session["username"] = ADMIN_USERNAME
                session["role"] = "admin"
                return redirect(url_for("index"))
            error = "Invalid credentials"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout() -> Any:
        session.clear()
        return redirect(url_for("login"))


def create_landing_app(database_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    app.config["RULES_ENGINE_URL"] = os.environ.get("RULES_ENGINE_URL", "http://localhost:8001")
    app.config["DESIGN_URL"] = os.environ.get("DESIGN_URL", "http://localhost:8002")
    app.config["END_USER_URL"] = os.environ.get("END_USER_URL", "http://localhost:8002")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.get("/")
    def index() -> str:
        conn = connect(_db_path(app))
        rulesets = conn.execute(
            "SELECT id, name, environment, created_at FROM rulesets ORDER BY id DESC LIMIT 20"
        ).fetchall()
        enhancements = conn.execute(
            "SELECT id, title, status, notes, created_at FROM frontend_enhancements ORDER BY id DESC LIMIT 20"
        ).fetchall()
        configurations = conn.execute(
            "SELECT id, customer_id, environment, updated_at FROM configuration_states ORDER BY id DESC LIMIT 20"
        ).fetchall()
        return render_template(
            "landing/index.html",
            rulesets=rulesets,
            enhancements=enhancements,
            configurations=configurations,
            rules_engine_url=app.config["RULES_ENGINE_URL"],
            design_url=app.config["DESIGN_URL"],
            end_user_url=app.config["END_USER_URL"],
        )

    @app.post("/enhancements")
    def add_enhancement() -> Any:
        title = request.form.get("title", "Untitled").strip() or "Untitled"
        status = request.form.get("status", "planned").strip() or "planned"
        notes = request.form.get("notes", "").strip()
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                "INSERT INTO frontend_enhancements(title, status, notes) VALUES (?, ?, ?)",
                (title, status, notes),
            )
        return redirect(url_for("index"))

    return app


def create_rules_engine_app(database_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.get("/")
    def index() -> str:
        conn = connect(_db_path(app))
        selected_ruleset_id = request.args.get("edit", type=int)
        selected_ruleset = None
        if selected_ruleset_id:
            selected_ruleset = conn.execute(
                "SELECT * FROM rulesets WHERE id = ?", (selected_ruleset_id,)
            ).fetchone()
        rulesets = conn.execute(
            """
            SELECT id, name, environment, product_name, category, subcategory, version, payload, created_at
            FROM rulesets
            ORDER BY product_name, category, subcategory, version DESC, id DESC
            """
        ).fetchall()
        deployments = conn.execute("SELECT environment, ruleset_id, deployed_at FROM deployments").fetchall()
        return render_template(
            "rules_engine/index.html",
            rulesets=rulesets,
            deployments=deployments,
            selected_ruleset=selected_ruleset,
        )

    @app.post("/rulesets")
    def create_ruleset() -> Any:
        payload = request.form.get("payload", "")
        name = request.form.get("name", "Untitled Ruleset")
        environment = request.form.get("environment", "dev")
        product_name = request.form.get("product_name", "default-product").strip() or "default-product"
        category = request.form.get("category", "general").strip() or "general"
        subcategory = request.form.get("subcategory", "default").strip() or "default"
        version = int(request.form.get("version", "1"))
        ruleset_id = request.form.get("ruleset_id", "").strip()
        parsed = normalize_ruleset(json.loads(payload))
        conn = connect(_db_path(app))
        with conn:
            if ruleset_id:
                conn.execute(
                    """
                    UPDATE rulesets
                    SET name = ?, environment = ?, product_name = ?, category = ?, subcategory = ?, version = ?, payload = ?
                    WHERE id = ?
                    """,
                    (
                        name,
                        environment,
                        product_name,
                        category,
                        subcategory,
                        version,
                        json_dumps(parsed),
                        int(ruleset_id),
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO rulesets(name, environment, product_name, category, subcategory, version, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, environment, product_name, category, subcategory, version, json_dumps(parsed)),
                )
        return redirect(url_for("index"))

    @app.post("/deploy/<int:ruleset_id>")
    def deploy(ruleset_id: int) -> Any:
        environment = request.form.get("environment", "dev")
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                """
                INSERT INTO deployments(environment, ruleset_id) VALUES (?, ?)
                ON CONFLICT(environment) DO UPDATE SET
                ruleset_id = excluded.ruleset_id,
                deployed_at = CURRENT_TIMESTAMP
                """,
                (environment, ruleset_id),
            )
        return redirect(url_for("index"))

    @app.post("/optimize")
    def optimize() -> Any:
        request_data = request.get_json(force=True)
        conn = connect(_db_path(app))
        ruleset = _load_deployed_rules(conn, request_data["environment"])
        result = optimize_configuration(
            domains=request_data["domains"],
            objective=request_data["objective"],
            ruleset=ruleset,
            maximize=bool(request_data.get("maximize", False)),
        )
        return jsonify(result)

    return app


def create_configurator_app(database_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.get("/")
    def index() -> str:
        return render_template("configurator/index.html")

    @app.post("/api/evaluate")
    def evaluate() -> Any:
        payload = request.get_json(force=True)
        customer_id = payload["customer_id"]
        api_key = payload["api_key"]
        environment = payload["environment"]

        conn = connect(_db_path(app))
        if not _authorize(conn, customer_id, api_key, environment):
            abort(403)

        configuration = payload["configuration"]
        ruleset = _load_deployed_rules(conn, environment)
        evaluated = evaluate_rules(ruleset, configuration)
        response = {
            "valid": evaluated.valid,
            "calculations": evaluated.calculations,
            "violations": evaluated.violations,
            "resolved_configuration": evaluated.resolved_configuration,
        }

        with conn:
            conn.execute(
                "INSERT INTO configuration_states(customer_id, environment, state) VALUES (?, ?, ?)",
                (customer_id, environment, json_dumps(evaluated.resolved_configuration)),
            )

        return jsonify(response)

    @app.post("/api/submit")
    def submit() -> Any:
        payload = request.get_json(force=True)
        customer_id = payload["customer_id"]
        api_key = payload["api_key"]
        environment = payload["environment"]

        conn = connect(_db_path(app))
        if not _authorize(conn, customer_id, api_key, environment):
            abort(403)

        specification = payload["specification"]
        with conn:
            conn.execute(
                "INSERT INTO specifications(customer_id, environment, specification) VALUES (?, ?, ?)",
                (customer_id, environment, json_dumps(specification)),
            )
        return jsonify({"status": "submitted"})

    return app
