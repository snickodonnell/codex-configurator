from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import BadRequest, HTTPException

from .db import connect, init_db, json_dumps
from .rules_engine import (
    RulesParseError,
    evaluate_rules,
    evaluate_workspace_rules,
    infer_memo_parameters,
    normalize_ruleset,
    optimize_configuration,
    parse_ruleset_pseudocode,
    ruleset_to_pseudocode,
    trace_ruleset_execution,
)


DEFAULT_RULESET = {
    "memo_parameters": [
        {
            "name": "quantity",
            "label": "Quantity",
            "data_type": "number",
            "parameter_class": "required_input",
            "rules_engine_property": "quantity",
        },
        {
            "name": "base_price",
            "label": "Base Price",
            "data_type": "number",
            "parameter_class": "required_input",
            "rules_engine_property": "base_price",
        },
        {
            "name": "discount",
            "label": "Discount",
            "data_type": "number",
            "parameter_class": "optional_input",
            "rules_engine_property": "discount",
        },
        {
            "name": "region",
            "label": "Region",
            "data_type": "string",
            "parameter_class": "required_input",
            "rules_engine_property": "region",
        },
        {
            "name": "unit_price",
            "label": "Unit Price",
            "data_type": "number",
            "parameter_class": "intermediate",
            "rules_engine_property": "unit_price",
        },
        {
            "name": "total_price",
            "label": "Total Price",
            "data_type": "number",
            "parameter_class": "intermediate",
            "rules_engine_property": "total_price",
        },
    ],
    "constraints": [
        {"expression": "quantity >= 1", "reason_code": "ERR_QUANTITY_REQUIRED"},
        {
            "expression": "(region != 'EU') or (discount <= 0.2)",
            "reason_code": "ERR_EU_DISCOUNT_HIGH",
        },
    ],
    "calculations": [
        {"name": "unit_price", "formula": "base_price * (1 - discount)"},
        {"name": "total_price", "formula": "unit_price * quantity"},
    ],
}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"
UX_EDITOR_USERNAME = "ux-admin"
UX_EDITOR_PASSWORD = "ux-admin"


def _db_path(app: Flask) -> Path:
    return Path(app.config["DATABASE_PATH"])


def _configure_observability(app: Flask, app_name: str) -> None:
    app.config["APP_NAME"] = app_name
    level_name = os.environ.get("APP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    app.logger.setLevel(level)


def _is_api_request() -> bool:
    return request.path.startswith("/api/") or request.path == "/optimize"


def _configure_error_handlers(app: Flask) -> None:
    @app.errorhandler(BadRequest)
    def handle_bad_request(error: BadRequest) -> Any:
        app.logger.warning("bad_request", extra={"path": request.path, "method": request.method, "error": str(error)})
        if _is_api_request():
            return jsonify({"error": "invalid request payload"}), 400
        return error

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> Any:
        app.logger.warning(
            "http_error",
            extra={"path": request.path, "method": request.method, "status_code": error.code, "error": error.description},
        )
        if _is_api_request():
            return jsonify({"error": error.description}), error.code
        return error

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> Any:
        app.logger.exception("unexpected_error", extra={"path": request.path, "method": request.method})
        if _is_api_request():
            return jsonify({"error": "internal server error"}), 500
        raise error


def _log_configuration_state_change(
    app: Flask,
    source: str,
    customer_id: str,
    environment: str,
    state: dict[str, Any],
) -> None:
    app.logger.info(
        "configuration_state_changed",
        extra={
            "source": source,
            "customer_id": customer_id,
            "environment": environment,
            "parameter_count": len(state),
            "keys": sorted(state.keys()),
        },
    )


def _load_deployed_ruleset(conn: Any, environment: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            r.id AS ruleset_id,
            r.product_name,
            r.category,
            r.subcategory,
            r.version,
            r.payload
        FROM deployments d
        JOIN rulesets r ON d.ruleset_id = r.id
        WHERE d.environment = ?
        """,
        (environment,),
    ).fetchone()

    if row is None:
        return {
            "ruleset_id": None,
            "product_name": "default-product",
            "category": "general",
            "subcategory": "default",
            "version": 1,
            "rules": normalize_ruleset(DEFAULT_RULESET),
        }

    return {
        "ruleset_id": row["ruleset_id"],
        "product_name": row["product_name"],
        "category": row["category"],
        "subcategory": row["subcategory"],
        "version": row["version"],
        "rules": normalize_ruleset(json.loads(row["payload"])),
    }




def _parameter_governance(parameter: dict[str, Any]) -> list[str]:
    data_type = str(parameter.get("data_type", "string"))
    parameter_class = str(parameter.get("parameter_class", "optional_input"))
    if parameter_class == "intermediate":
        return ["text"]
    if data_type == "boolean":
        return ["radio_boolean", "dropdown", "button_group"]
    if data_type == "number":
        return ["number", "slider", "dropdown", "button_group"]
    return ["text", "dropdown", "button_group"]


def _rules_fingerprint(ruleset: dict[str, Any]) -> str:
    parameters = []
    for parameter in infer_memo_parameters(ruleset):
        parameters.append(
            {
                "name": parameter["name"],
                "data_type": parameter["data_type"],
                "parameter_class": parameter["parameter_class"],
                "allowed_controls": _parameter_governance(parameter),
            }
        )
    return json_dumps({"parameters": sorted(parameters, key=lambda item: item["name"])})


def _sync_ruleset_workflow(conn: Any, ruleset_id: int, environment: str, ruleset: dict[str, Any]) -> None:
    fingerprint = _rules_fingerprint(ruleset)
    previous = conn.execute(
        """
        SELECT wf.rules_fingerprint
        FROM release_workflows wf
        JOIN rulesets r ON wf.ruleset_id = r.id
        WHERE r.environment = ? AND r.id != ?
        ORDER BY r.version DESC, r.id DESC
        LIMIT 1
        """,
        (environment, ruleset_id),
    ).fetchone()
    requires_ux_update = 0
    if previous and previous["rules_fingerprint"] != fingerprint:
        requires_ux_update = 1

    conn.execute(
        "DELETE FROM ruleset_parameter_profiles WHERE ruleset_id = ?",
        (ruleset_id,),
    )
    parameters = infer_memo_parameters(ruleset)
    conn.executemany(
        """
        INSERT INTO ruleset_parameter_profiles(ruleset_id, parameter_name, data_type, parameter_class, governance_control_types)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                ruleset_id,
                parameter["name"],
                parameter["data_type"],
                parameter["parameter_class"],
                json_dumps({"allowed": _parameter_governance(parameter)}),
            )
            for parameter in parameters
        ],
    )

    conn.execute(
        """
        INSERT INTO release_workflows(ruleset_id, environment, rules_fingerprint, state, requires_ux_update, ux_schema_version)
        VALUES (?, ?, ?, 'draft', ?, 0)
        ON CONFLICT(ruleset_id) DO UPDATE SET
            environment = excluded.environment,
            rules_fingerprint = excluded.rules_fingerprint,
            state = 'draft',
            requires_ux_update = excluded.requires_ux_update,
            updated_at = CURRENT_TIMESTAMP
        """,
        (ruleset_id, environment, fingerprint, requires_ux_update),
    )


def _workflow_for_ruleset(conn: Any, ruleset_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, ruleset_id, environment, state, requires_ux_update, ux_schema_version, approved_by, updated_at
        FROM release_workflows WHERE ruleset_id = ?
        """,
        (ruleset_id,),
    ).fetchone()
    return dict(row) if row else None

def _build_configuration_memo_schema(ruleset: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    params = infer_memo_parameters(ruleset)
    grouped = {
        "required_input": [item for item in params if item["parameter_class"] == "required_input"],
        "optional_input": [item for item in params if item["parameter_class"] == "optional_input"],
        "intermediate": [item for item in params if item["parameter_class"] == "intermediate"],
    }
    return {
        "product_name": metadata["product_name"],
        "category": metadata["category"],
        "subcategory": metadata["subcategory"],
        "version": metadata["version"],
        "parameters": params,
        **grouped,
    }


def _authorize(conn: Any, customer_id: str, api_key: str, environment: str) -> bool:
    row = conn.execute(
        "SELECT api_key, environments FROM customer_access WHERE customer_id = ?", (customer_id,)
    ).fetchone()
    if not row or row["api_key"] != api_key:
        return False
    environments = json.loads(row["environments"])
    return environment in environments


def _is_logged_in() -> bool:
    return bool(session.get("username") and session.get("role"))


def _is_admin() -> bool:
    return session.get("role") == "admin"


def _is_frontend_editor() -> bool:
    return session.get("role") in {"admin", "frontend_editor"}


def _json_body() -> dict[str, Any]:
    return request.get_json(force=True, silent=False) or {}


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
                app.logger.info("login_success", extra={"username": username, "role": "admin"})
                return redirect(url_for("index"))
            if username == UX_EDITOR_USERNAME and password == UX_EDITOR_PASSWORD:
                session["username"] = UX_EDITOR_USERNAME
                session["role"] = "frontend_editor"
                app.logger.info("login_success", extra={"username": username, "role": "frontend_editor"})
                return redirect(url_for("index"))
            app.logger.warning("login_failed", extra={"username": username})
            error = "Invalid credentials"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout() -> Any:
        app.logger.info("logout", extra={"username": session.get("username", "anonymous")})
        session.clear()
        return redirect(url_for("login"))


def create_landing_app(database_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    _configure_observability(app, "landing")
    _configure_error_handlers(app)
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    app.config["RULES_ENGINE_URL"] = os.environ.get("RULES_ENGINE_URL", "http://localhost:8001")
    app.config["RULE_CANVAS_URL"] = os.environ.get("RULE_CANVAS_URL", "http://localhost:8001")
    app.config["EXPERIENCE_STUDIO_URL"] = os.environ.get("EXPERIENCE_STUDIO_URL", "http://localhost:8003")
    app.config["SHOP_FLOOR_URL"] = os.environ.get("SHOP_FLOOR_URL", "http://localhost:8002")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.before_request
    def require_admin_role() -> Any:
        if request.endpoint in {"login", "logout", "static"}:
            return None
        if _is_admin():
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "admin role required"}), 403
        return "Forbidden", 403

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
            rule_canvas_url=app.config["RULE_CANVAS_URL"],
            experience_studio_url=app.config["EXPERIENCE_STUDIO_URL"],
            shop_floor_url=app.config["SHOP_FLOOR_URL"],
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
    _configure_observability(app, "rules")
    _configure_error_handlers(app)
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.before_request
    def require_admin_role() -> Any:
        if request.endpoint in {"login", "logout", "static"}:
            return None
        if _is_admin():
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "admin role required"}), 403
        return "Forbidden", 403

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
        workflow_rows = conn.execute(
            "SELECT ruleset_id, state, requires_ux_update, ux_schema_version, approved_by, updated_at FROM release_workflows"
        ).fetchall()
        workflows = {row["ruleset_id"]: dict(row) for row in workflow_rows}
        selected_pseudocode = ""
        if selected_ruleset:
            selected_pseudocode = ruleset_to_pseudocode(json.loads(selected_ruleset["payload"]))

        return render_template(
            "rules_engine/index.html",
            rulesets=rulesets,
            deployments=deployments,
            selected_ruleset=selected_ruleset,
            selected_pseudocode=selected_pseudocode,
            parse_error=request.args.get("error", ""),
            workflows=workflows,
        )

    @app.get("/api/workspace")
    def get_workspace() -> Any:
        conn = connect(_db_path(app))
        products = conn.execute(
            "SELECT id, name, description FROM workspace_products ORDER BY name"
        ).fetchall()
        categories = conn.execute(
            "SELECT id, product_id, name, parent_id, position FROM workspace_categories ORDER BY position, id"
        ).fetchall()
        rules = conn.execute(
            """
            SELECT id, product_id, category_id, subcategory_id, rule_type, target, expression, message, position, is_editable
            FROM workspace_rules
            ORDER BY position, id
            """
        ).fetchall()

        categories_by_product: dict[int, list[dict[str, Any]]] = {}
        for category in categories:
            categories_by_product.setdefault(category["product_id"], []).append(dict(category))

        rules_by_product: dict[int, list[dict[str, Any]]] = {}
        for rule in rules:
            rules_by_product.setdefault(rule["product_id"], []).append(dict(rule))

        payload = []
        for product in products:
            product_categories = categories_by_product.get(product["id"], [])
            top_level = [item for item in product_categories if item["parent_id"] is None]
            subcategories = [item for item in product_categories if item["parent_id"] is not None]
            sub_by_parent: dict[int, list[dict[str, Any]]] = {}
            for sub in subcategories:
                sub_by_parent.setdefault(sub["parent_id"], []).append(sub)

            product_rules = rules_by_product.get(product["id"], [])
            rules_by_bucket: dict[tuple[int, int | None], list[dict[str, Any]]] = {}
            for rule in product_rules:
                key = (int(rule["category_id"]), rule["subcategory_id"])
                rules_by_bucket.setdefault(key, []).append(rule)

            assembled_categories = []
            for category in top_level:
                category_id = int(category["id"])
                assembled_sub = []
                for sub in sorted(sub_by_parent.get(category_id, []), key=lambda item: (item["position"], item["id"])):
                    assembled_sub.append(
                        {
                            **sub,
                            "rules": rules_by_bucket.get((category_id, sub["id"]), []),
                        }
                    )
                assembled_categories.append(
                    {
                        **category,
                        "rules": rules_by_bucket.get((category_id, None), []),
                        "subcategories": assembled_sub,
                    }
                )

            payload.append({**dict(product), "categories": assembled_categories})

        return jsonify({"products": payload})

    @app.post("/api/workspace/products")
    def create_workspace_product() -> Any:
        body = _json_body()
        name = str(body.get("name", "")).strip()
        if not name:
            return jsonify({"error": "name is required"}), 400
        description = str(body.get("description", "")).strip()
        conn = connect(_db_path(app))
        with conn:
            cursor = conn.execute(
                "INSERT INTO workspace_products(name, description) VALUES (?, ?)",
                (name, description),
            )
        return jsonify({"id": int(cursor.lastrowid), "name": name, "description": description}), 201

    @app.put("/api/workspace/products/<int:product_id>")
    def update_workspace_product(product_id: int) -> Any:
        body = _json_body()
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                "UPDATE workspace_products SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (str(body.get("name", "")).strip() or f"Product {product_id}", str(body.get("description", "")).strip(), product_id),
            )
        return jsonify({"status": "ok"})

    @app.delete("/api/workspace/products/<int:product_id>")
    def delete_workspace_product(product_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            conn.execute("DELETE FROM workspace_rules WHERE product_id = ?", (product_id,))
            conn.execute("DELETE FROM workspace_categories WHERE product_id = ?", (product_id,))
            conn.execute("DELETE FROM workspace_products WHERE id = ?", (product_id,))
        return jsonify({"status": "deleted"})

    @app.post("/api/workspace/categories")
    def create_workspace_category() -> Any:
        body = _json_body()
        product_id = int(body["product_id"])
        parent_id = body.get("parent_id")
        name = str(body.get("name", "")).strip() or "Untitled"
        position = int(body.get("position", 0))
        conn = connect(_db_path(app))
        with conn:
            cursor = conn.execute(
                "INSERT INTO workspace_categories(product_id, name, parent_id, position) VALUES (?, ?, ?, ?)",
                (product_id, name, parent_id, position),
            )
        return jsonify({"id": int(cursor.lastrowid)}), 201

    @app.put("/api/workspace/categories/<int:category_id>")
    def update_workspace_category(category_id: int) -> Any:
        body = _json_body()
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                "UPDATE workspace_categories SET name = ?, position = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (str(body.get("name", "")).strip() or "Untitled", int(body.get("position", 0)), category_id),
            )
        return jsonify({"status": "ok"})

    @app.delete("/api/workspace/categories/<int:category_id>")
    def delete_workspace_category(category_id: int) -> Any:
        conn = connect(_db_path(app))
        child_ids = [row["id"] for row in conn.execute("SELECT id FROM workspace_categories WHERE parent_id = ?", (category_id,))]
        with conn:
            conn.execute("DELETE FROM workspace_rules WHERE category_id = ?", (category_id,))
            for child_id in child_ids:
                conn.execute("DELETE FROM workspace_rules WHERE subcategory_id = ?", (child_id,))
            if child_ids:
                conn.executemany("DELETE FROM workspace_categories WHERE id = ?", [(child_id,) for child_id in child_ids])
            conn.execute("DELETE FROM workspace_categories WHERE id = ?", (category_id,))
        return jsonify({"status": "deleted"})

    @app.post("/api/workspace/rules")
    def create_workspace_rule() -> Any:
        body = _json_body()
        conn = connect(_db_path(app))
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO workspace_rules(product_id, category_id, subcategory_id, rule_type, target, expression, message, position, is_editable)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(body["product_id"]),
                    int(body["category_id"]),
                    body.get("subcategory_id"),
                    str(body.get("rule_type", "constraint")),
                    str(body.get("target", "")),
                    str(body.get("expression", "1 == 1")),
                    str(body.get("message", "")),
                    int(body.get("position", 0)),
                    0,
                ),
            )
        return jsonify({"id": int(cursor.lastrowid)}), 201

    @app.put("/api/workspace/rules/<int:rule_id>")
    def update_workspace_rule(rule_id: int) -> Any:
        body = _json_body()
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                """
                UPDATE workspace_rules
                SET rule_type = ?, target = ?, expression = ?, message = ?, position = ?, is_editable = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    str(body.get("rule_type", "constraint")),
                    str(body.get("target", "")),
                    str(body.get("expression", "1 == 1")),
                    str(body.get("message", "")),
                    int(body.get("position", 0)),
                    1 if body.get("is_editable") else 0,
                    rule_id,
                ),
            )
        return jsonify({"status": "ok"})

    @app.post("/api/workspace/rules/<int:rule_id>/editable")
    def set_workspace_rule_editable(rule_id: int) -> Any:
        body = _json_body()
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                "UPDATE workspace_rules SET is_editable = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if bool(body.get("is_editable", True)) else 0, rule_id),
            )
        return jsonify({"status": "ok"})


    @app.post("/api/workspace/rules/<int:rule_id>/position")
    def update_workspace_rule_position(rule_id: int) -> Any:
        body = _json_body()
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                "UPDATE workspace_rules SET position = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (int(body.get("position", 0)), rule_id),
            )
        return jsonify({"status": "ok"})

    @app.delete("/api/workspace/rules/<int:rule_id>")
    def delete_workspace_rule(rule_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            conn.execute("DELETE FROM workspace_rules WHERE id = ?", (rule_id,))
        return jsonify({"status": "deleted"})

    @app.post("/api/trace")
    def trace_ruleset() -> Any:
        body = _json_body()
        configuration = body.get("configuration", {})
        if not isinstance(configuration, dict):
            return jsonify({"error": "configuration must be an object"}), 400

        conn = connect(_db_path(app))
        ruleset_payload: dict[str, Any]
        ruleset_id = body.get("ruleset_id")
        pseudo_rules = str(body.get("pseudo_rules") or "").strip()
        payload = body.get("payload")

        try:
            if ruleset_id is not None:
                row = conn.execute("SELECT payload FROM rulesets WHERE id = ?", (int(ruleset_id),)).fetchone()
                if row is None:
                    return jsonify({"error": "ruleset not found"}), 404
                ruleset_payload = normalize_ruleset(json.loads(row["payload"]))
            elif pseudo_rules:
                ruleset_payload = parse_ruleset_pseudocode(pseudo_rules)
            elif payload:
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if not isinstance(payload, dict):
                    raise ValueError("payload must be a JSON object")
                ruleset_payload = normalize_ruleset(payload)
            else:
                return jsonify({"error": "provide ruleset_id, pseudo_rules, or payload"}), 400

            traced = trace_ruleset_execution(ruleset_payload, configuration)
        except (ValueError, TypeError, json.JSONDecodeError, RulesParseError) as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify(
            {
                "valid": traced.valid,
                "resolved_configuration": traced.resolved_configuration,
                "calculations": traced.calculations,
                "violations": traced.violations,
                "steps": traced.steps,
            }
        )

    @app.post("/rulesets")
    def create_ruleset() -> Any:
        payload = request.form.get("payload", "").strip()
        pseudo_rules = request.form.get("pseudo_rules", "").strip()
        name = request.form.get("name", "Untitled Ruleset")
        environment = request.form.get("environment", "dev")
        product_name = request.form.get("product_name", "default-product").strip() or "default-product"
        category = request.form.get("category", "general").strip() or "general"
        subcategory = request.form.get("subcategory", "default").strip() or "default"
        version = int(request.form.get("version", "1"))
        ruleset_id = request.form.get("ruleset_id", "").strip()

        try:
            if pseudo_rules:
                parsed = parse_ruleset_pseudocode(pseudo_rules)
            elif payload:
                parsed = normalize_ruleset(json.loads(payload))
            else:
                raise RulesParseError("Provide pseudo rules or JSON payload")
        except (json.JSONDecodeError, RulesParseError, ValueError) as exc:
            target = int(ruleset_id) if ruleset_id else ""
            return redirect(url_for("index", edit=target, error=str(exc)))

        normalized = normalize_ruleset(parsed)
        conn = connect(_db_path(app))
        persisted_ruleset_id = int(ruleset_id) if ruleset_id else None
        with conn:
            if persisted_ruleset_id is not None:
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
                        json_dumps(normalized),
                        persisted_ruleset_id,
                    ),
                )
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO rulesets(name, environment, product_name, category, subcategory, version, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        environment,
                        product_name,
                        category,
                        subcategory,
                        version,
                        json_dumps(normalized),
                    ),
                )
                persisted_ruleset_id = int(cursor.lastrowid)

            _sync_ruleset_workflow(conn, int(persisted_ruleset_id), environment, normalized)
        app.logger.info(
            "ruleset_saved",
            extra={
                "ruleset_id": int(persisted_ruleset_id),
                "environment": environment,
                "product_name": product_name,
                "category": category,
                "subcategory": subcategory,
                "version": version,
            },
        )
        return redirect(url_for("index"))

    @app.post("/workflow/<int:ruleset_id>/send-to-studio")
    def send_to_studio(ruleset_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            workflow = _workflow_for_ruleset(conn, ruleset_id)
            if not workflow:
                return jsonify({"error": "workflow not found"}), 404
            conn.execute(
                "UPDATE release_workflows SET state = 'in_studio', updated_at = CURRENT_TIMESTAMP WHERE ruleset_id = ?",
                (ruleset_id,),
            )
        app.logger.info("workflow_state_changed", extra={"ruleset_id": ruleset_id, "state": "in_studio"})
        return redirect(url_for("index"))

    @app.post("/workflow/<int:ruleset_id>/request-approval")
    def request_approval(ruleset_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            workflow = _workflow_for_ruleset(conn, ruleset_id)
            if not workflow:
                return jsonify({"error": "workflow not found"}), 404
            if workflow["requires_ux_update"]:
                return redirect(url_for("index", error="UX mapping must be refreshed before approval"))
            conn.execute(
                "UPDATE release_workflows SET state = 'pending_approval', updated_at = CURRENT_TIMESTAMP WHERE ruleset_id = ?",
                (ruleset_id,),
            )
        app.logger.info("workflow_state_changed", extra={"ruleset_id": ruleset_id, "state": "pending_approval"})
        return redirect(url_for("index"))

    @app.post("/workflow/<int:ruleset_id>/approve")
    def approve_release(ruleset_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            workflow = _workflow_for_ruleset(conn, ruleset_id)
            if not workflow:
                return jsonify({"error": "workflow not found"}), 404
            if workflow["requires_ux_update"]:
                return redirect(url_for("index", error="Cannot approve while UX update is required"))
            conn.execute(
                """
                UPDATE release_workflows
                SET state = 'approved', approved_by = ?, updated_at = CURRENT_TIMESTAMP
                WHERE ruleset_id = ?
                """,
                (session.get("username", "admin"), ruleset_id),
            )
        app.logger.info("workflow_state_changed", extra={"ruleset_id": ruleset_id, "state": "approved"})
        return redirect(url_for("index"))

    @app.post("/deploy/<int:ruleset_id>")
    def deploy(ruleset_id: int) -> Any:
        environment = request.form.get("environment", "dev")
        conn = connect(_db_path(app))
        workflow = _workflow_for_ruleset(conn, ruleset_id)
        if workflow and workflow["state"] in {"in_studio", "pending_approval", "approved"}:
            if workflow["state"] != "approved" or workflow["requires_ux_update"]:
                return redirect(url_for("index", error="Release must be approved with synced UX mapping before deploy"))

        with conn:
            previous = conn.execute("SELECT ruleset_id FROM deployments WHERE environment = ?", (environment,)).fetchone()
            conn.execute(
                """
                INSERT INTO deployments(environment, ruleset_id) VALUES (?, ?)
                ON CONFLICT(environment) DO UPDATE SET
                ruleset_id = excluded.ruleset_id,
                deployed_at = CURRENT_TIMESTAMP
                """,
                (environment, ruleset_id),
            )
            conn.execute(
                "INSERT INTO deployment_history(environment, ruleset_id, action) VALUES (?, ?, 'deploy')",
                (environment, ruleset_id),
            )
            if previous:
                conn.execute(
                    "INSERT INTO deployment_history(environment, ruleset_id, action) VALUES (?, ?, 'replaced')",
                    (environment, int(previous["ruleset_id"])),
                )
            conn.execute(
                "UPDATE release_workflows SET state = 'deployed', updated_at = CURRENT_TIMESTAMP WHERE ruleset_id = ?",
                (ruleset_id,),
            )
        app.logger.info("deployment_changed", extra={"environment": environment, "ruleset_id": ruleset_id, "action": "deploy"})
        return redirect(url_for("index"))

    @app.post("/rollback")
    def rollback_deployment() -> Any:
        environment = request.form.get("environment", "dev")
        conn = connect(_db_path(app))
        history = conn.execute(
            """
            SELECT ruleset_id FROM deployment_history
            WHERE environment = ? AND action = 'deploy'
            ORDER BY id DESC LIMIT 2
            """,
            (environment,),
        ).fetchall()
        if len(history) < 2:
            return redirect(url_for("index", error="No previous deployment available for rollback"))
        previous_ruleset_id = int(history[1]["ruleset_id"])
        with conn:
            conn.execute(
                "UPDATE deployments SET ruleset_id = ?, deployed_at = CURRENT_TIMESTAMP WHERE environment = ?",
                (previous_ruleset_id, environment),
            )
            conn.execute(
                "INSERT INTO deployment_history(environment, ruleset_id, action) VALUES (?, ?, 'rollback')",
                (environment, previous_ruleset_id),
            )
            conn.execute(
                "UPDATE release_workflows SET state = 'rolled_back', updated_at = CURRENT_TIMESTAMP WHERE ruleset_id = ?",
                (previous_ruleset_id,),
            )
        app.logger.info("deployment_changed", extra={"environment": environment, "ruleset_id": previous_ruleset_id, "action": "rollback"})
        return redirect(url_for("index"))

    @app.post("/optimize")
    def optimize() -> Any:
        request_data = request.get_json(force=True)
        conn = connect(_db_path(app))
        ruleset = _load_deployed_ruleset(conn, request_data["environment"])["rules"]
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
    _configure_observability(app, "configurator")
    _configure_error_handlers(app)
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.before_request
    def require_editor_role() -> Any:
        if request.endpoint in {"login", "logout", "static"}:
            return None
        if _is_frontend_editor():
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "frontend editor role required"}), 403
        return "Forbidden", 403

    def _workspace_rules_for_product(conn: Any, workspace_product_id: int) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT
                wr.id,
                wr.rule_type,
                wr.target,
                wr.expression,
                wr.message,
                wr.position,
                wr.is_editable,
                c1.id AS category_id,
                c1.name AS category_name,
                c2.id AS subcategory_id,
                c2.name AS subcategory_name
            FROM workspace_rules wr
            JOIN workspace_categories c1 ON wr.category_id = c1.id
            LEFT JOIN workspace_categories c2 ON wr.subcategory_id = c2.id
            WHERE wr.product_id = ?
            ORDER BY c1.position, c1.id, c2.position, c2.id, wr.position, wr.id
            """,
            (workspace_product_id,),
        ).fetchall()
        return [dict(row) for row in rows]


    def _include_meta_flag(payload: dict[str, Any]) -> bool:
        candidate = request.args.get("include_meta")
        if candidate is None:
            candidate = payload.get("include_meta")
        if isinstance(candidate, bool):
            return candidate
        if isinstance(candidate, str):
            return candidate.strip().lower() in {"1", "true", "yes", "on"}
        return bool(candidate)

    def _serialize_violations(violations: list[Any]) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
        public_violations: list[dict[str, Any]] = []
        violation_codes: list[str] = []
        debug_violations: list[dict[str, Any]] = []

        for violation in violations:
            code = str(getattr(violation, "code"))
            recommended_severity = str(getattr(violation, "recommended_severity"))
            rule = dict(getattr(violation, "rule"))
            meta = dict(getattr(violation, "meta"))

            public_violations.append(
                {
                    "code": code,
                    "recommended_severity": recommended_severity,
                    "rule": rule,
                }
            )
            violation_codes.append(code)
            debug_violations.append(
                {
                    "code": code,
                    "recommended_severity": recommended_severity,
                    "rule": rule,
                    "meta": meta,
                }
            )

        return public_violations, violation_codes, debug_violations

    def _log_constraint_violations(
        violations_debug: list[dict[str, Any]],
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        context_payload = dict(context or {})
        for violation in violations_debug:
            app.logger.info(
                "constraint_violation",
                extra={
                    "code": violation["code"],
                    "recommended_severity": violation["recommended_severity"],
                    "meta": violation["meta"],
                    **context_payload,
                },
            )

    def _project_payload(conn: Any, project_id: int) -> dict[str, Any] | None:
        project = conn.execute(
            """
            SELECT id, customer_id, environment, name, project_status, notes, created_at, updated_at
            FROM customer_projects
            WHERE id = ?
            """,
            (project_id,),
        ).fetchone()
        if project is None:
            return None

        product_rows = conn.execute(
            """
            SELECT
                cpp.id,
                cpp.project_id,
                cpp.workspace_product_id,
                cpp.quantity,
                cpp.configuration_status,
                cpp.configuration_state,
                cpp.last_evaluated_at,
                cpp.created_at,
                cpp.updated_at,
                wp.name AS product_name,
                wp.description AS product_description
            FROM customer_project_products cpp
            JOIN workspace_products wp ON wp.id = cpp.workspace_product_id
            WHERE cpp.project_id = ?
            ORDER BY cpp.id
            """,
            (project_id,),
        ).fetchall()

        products: list[dict[str, Any]] = []
        for row in product_rows:
            item = dict(row)
            item["configuration_state"] = json.loads(item["configuration_state"] or "{}")
            item["workspace_rules"] = _workspace_rules_for_product(conn, int(row["workspace_product_id"]))
            products.append(item)

        payload = dict(project)
        payload["products"] = products
        return payload

    def _all_projects(conn: Any, customer_id: str, environment: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT id
            FROM customer_projects
            WHERE customer_id = ? AND environment = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (customer_id, environment),
        ).fetchall()
        return [project for row in rows if (project := _project_payload(conn, int(row["id"]))) is not None]

    @app.get("/")
    def index() -> str:
        return render_template("configurator/index.html")

    @app.get("/api/workspace-products")
    def workspace_products() -> Any:
        conn = connect(_db_path(app))
        rows = conn.execute(
            "SELECT id, name, description FROM workspace_products ORDER BY name, id"
        ).fetchall()
        return jsonify({"products": [dict(row) for row in rows]})

    @app.get("/api/projects")
    def list_projects() -> Any:
        customer_id = request.args.get("customer_id", "demo-customer")
        environment = request.args.get("environment", "dev")
        conn = connect(_db_path(app))
        return jsonify({"projects": _all_projects(conn, customer_id, environment)})

    @app.post("/api/projects")
    def create_project() -> Any:
        body = request.get_json(force=True)
        customer_id = str(body.get("customer_id", "demo-customer")).strip() or "demo-customer"
        environment = str(body.get("environment", "dev")).strip() or "dev"
        name = str(body.get("name", "New Project")).strip() or "New Project"
        notes = str(body.get("notes", "")).strip()
        project_status = str(body.get("project_status", "draft")).strip() or "draft"

        conn = connect(_db_path(app))
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO customer_projects(customer_id, environment, name, project_status, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (customer_id, environment, name, project_status, notes),
            )
            project_id = int(cursor.lastrowid)
        project = _project_payload(conn, project_id)
        return jsonify(project), 201

    @app.put("/api/projects/<int:project_id>")
    def update_project(project_id: int) -> Any:
        body = request.get_json(force=True)
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                """
                UPDATE customer_projects
                SET name = ?, project_status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    str(body.get("name", "")).strip() or f"Project {project_id}",
                    str(body.get("project_status", "draft")).strip() or "draft",
                    str(body.get("notes", "")).strip(),
                    project_id,
                ),
            )
        project = _project_payload(conn, project_id)
        if project is None:
            abort(404)
        return jsonify(project)

    @app.delete("/api/projects/<int:project_id>")
    def delete_project(project_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            conn.execute("DELETE FROM customer_project_products WHERE project_id = ?", (project_id,))
            conn.execute("DELETE FROM customer_projects WHERE id = ?", (project_id,))
        return jsonify({"status": "deleted"})

    @app.post("/api/projects/<int:project_id>/products")
    def add_project_product(project_id: int) -> Any:
        body = request.get_json(force=True)
        workspace_product_id = int(body["workspace_product_id"])
        quantity = max(1, int(body.get("quantity", 1)))
        conn = connect(_db_path(app))
        with conn:
            existing = conn.execute(
                """
                SELECT id, quantity FROM customer_project_products
                WHERE project_id = ? AND workspace_product_id = ?
                """,
                (project_id, workspace_product_id),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE customer_project_products
                    SET quantity = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (quantity, int(existing["id"])),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO customer_project_products(project_id, workspace_product_id, quantity)
                    VALUES (?, ?, ?)
                    """,
                    (project_id, workspace_product_id, quantity),
                )
            conn.execute(
                "UPDATE customer_projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (project_id,),
            )
        project = _project_payload(conn, project_id)
        if project is None:
            abort(404)
        return jsonify(project)

    @app.put("/api/projects/<int:project_id>/products/<int:item_id>")
    def update_project_product(project_id: int, item_id: int) -> Any:
        body = request.get_json(force=True)
        quantity = max(1, int(body.get("quantity", 1)))
        configuration_status = str(body.get("configuration_status", "not_started")).strip() or "not_started"
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                """
                UPDATE customer_project_products
                SET quantity = ?, configuration_status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND project_id = ?
                """,
                (quantity, configuration_status, item_id, project_id),
            )
            conn.execute(
                "UPDATE customer_projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (project_id,),
            )
        project = _project_payload(conn, project_id)
        if project is None:
            abort(404)
        return jsonify(project)

    @app.delete("/api/projects/<int:project_id>/products/<int:item_id>")
    def delete_project_product(project_id: int, item_id: int) -> Any:
        conn = connect(_db_path(app))
        with conn:
            conn.execute(
                "DELETE FROM customer_project_products WHERE id = ? AND project_id = ?",
                (item_id, project_id),
            )
            conn.execute(
                "UPDATE customer_projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (project_id,),
            )
        project = _project_payload(conn, project_id)
        if project is None:
            abort(404)
        return jsonify(project)

    @app.get("/api/projects/<int:project_id>/configuration")
    def project_configuration(project_id: int) -> Any:
        item_id = request.args.get("item_id", type=int)
        if item_id is None:
            abort(400)

        conn = connect(_db_path(app))
        row = conn.execute(
            """
            SELECT cpp.id, cpp.workspace_product_id, cpp.configuration_state, wp.name AS product_name
            FROM customer_project_products cpp
            JOIN workspace_products wp ON wp.id = cpp.workspace_product_id
            WHERE cpp.project_id = ? AND cpp.id = ?
            """,
            (project_id, item_id),
        ).fetchone()
        if row is None:
            abort(404)

        project = _project_payload(conn, project_id)
        if project is None:
            abort(404)

        deployed = _load_deployed_ruleset(conn, project["environment"])
        schema = _build_configuration_memo_schema(deployed["rules"], deployed)
        rules = _workspace_rules_for_product(conn, int(row["workspace_product_id"]))

        controls_res = ui_schema().get_json()
        controls = controls_res["controls"]
        configured = json.loads(row["configuration_state"] or "{}")

        return jsonify({
            "project": project,
            "project_product_id": item_id,
            "product_name": row["product_name"],
            "schema": schema,
            "controls": controls,
            "workspace_rules": rules,
            "configuration_state": configured,
        })

    @app.post("/api/projects/<int:project_id>/products/<int:item_id>/evaluate")
    def evaluate_project_configuration(project_id: int, item_id: int) -> Any:
        payload = request.get_json(force=True)
        conn = connect(_db_path(app))
        row = conn.execute(
            """
            SELECT p.customer_id, p.environment, cpp.workspace_product_id
            FROM customer_projects p
            JOIN customer_project_products cpp ON cpp.project_id = p.id
            WHERE p.id = ? AND cpp.id = ?
            """,
            (project_id, item_id),
        ).fetchone()
        if row is None:
            abort(404)

        customer_id = payload.get("customer_id") or row["customer_id"]
        api_key = payload["api_key"]
        environment = row["environment"]
        if not _authorize(conn, str(customer_id), str(api_key), str(environment)):
            abort(403)

        configuration = payload.get("configuration", {})
        include_meta = _include_meta_flag(payload)
        deployed = _load_deployed_ruleset(conn, environment)
        evaluated = evaluate_rules(deployed["rules"], configuration)
        public_violations, violation_codes, violations_debug = _serialize_violations(evaluated.violations)
        _log_constraint_violations(
            violations_debug,
            context={
                "environment": str(environment),
                "customer_id": str(customer_id),
                "project_id": project_id,
                "project_product_id": item_id,
                "workspace_product_id": int(row["workspace_product_id"]),
            },
        )

        context = {**evaluated.resolved_configuration, **evaluated.calculations}
        workspace_rules = _workspace_rules_for_product(conn, int(row["workspace_product_id"]))
        workspace_evaluation = evaluate_workspace_rules(workspace_rules, context)
        studio_violations = [
            {
                "rule_id": violation.rule_id,
                "category": violation.category,
                "subcategory": violation.subcategory,
                "message": violation.message,
                "expression": violation.expression,
            }
            for violation in workspace_evaluation.violations
        ]

        status = "ready" if evaluated.valid and not studio_violations else "attention_required"
        project_status = "configured" if status == "ready" else "in_progress"

        with conn:
            conn.execute(
                """
                UPDATE customer_project_products
                SET configuration_state = ?, configuration_status = ?, last_evaluated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND project_id = ?
                """,
                (json_dumps(evaluated.resolved_configuration), status, item_id, project_id),
            )
            conn.execute(
                """
                UPDATE customer_projects
                SET project_status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (project_status, project_id),
            )
            conn.execute(
                "INSERT INTO configuration_states(customer_id, environment, state) VALUES (?, ?, ?)",
                (customer_id, environment, json_dumps(evaluated.resolved_configuration)),
            )

        _log_configuration_state_change(
            app,
            source="project.evaluate",
            customer_id=str(customer_id),
            environment=str(environment),
            state=evaluated.resolved_configuration,
        )

        response = {
            "valid": evaluated.valid,
            "calculations": evaluated.calculations,
            "violations": public_violations,
            "violation_codes": violation_codes,
            "studio_violations": studio_violations,
            "resolved_configuration": evaluated.resolved_configuration,
            "configuration_status": status,
            "project_status": project_status,
        }
        if include_meta:
            response["violations_debug"] = violations_debug

        return jsonify(response)

    @app.get("/api/configuration-memo")
    def configuration_memo() -> Any:
        environment = request.args.get("environment", "dev")
        conn = connect(_db_path(app))
        deployed = _load_deployed_ruleset(conn, environment)
        schema = _build_configuration_memo_schema(deployed["rules"], deployed)
        return jsonify(schema)

    @app.get("/api/ui-schema")
    def ui_schema() -> Any:
        environment = request.args.get("environment", "dev")
        conn = connect(_db_path(app))
        deployed = _load_deployed_ruleset(conn, environment)
        schema = _build_configuration_memo_schema(deployed["rules"], deployed)
        ruleset_id = int(deployed["ruleset_id"]) if deployed["ruleset_id"] is not None else None
        rows = []
        options = []
        if ruleset_id is not None:
            rows = conn.execute(
                """
                SELECT parameter_name, display_label, help_text, control_type, display_style,
                       min_value, max_value, step_value, placeholder, image_url, value_image_mode, is_required
                FROM ui_parameter_configs
                WHERE ruleset_id = ?
                ORDER BY parameter_name
                """,
                (ruleset_id,),
            ).fetchall()
            options = conn.execute(
                """
                SELECT parameter_name, option_value, option_label, option_order, image_url
                FROM ui_parameter_options
                WHERE ruleset_id = ?
                ORDER BY parameter_name, option_order, id
                """,
                (ruleset_id,),
            ).fetchall()

        by_name = {row["parameter_name"]: dict(row) for row in rows}
        options_by_name: dict[str, list[dict[str, Any]]] = {}
        for row in options:
            options_by_name.setdefault(row["parameter_name"], []).append(dict(row))

        controls = []
        for parameter in schema["parameters"]:
            configured = by_name.get(parameter["name"], {})
            controls.append({
                "parameter_name": parameter["name"],
                "display_label": configured.get("display_label") or parameter["label"],
                "help_text": configured.get("help_text") or "",
                "control_type": configured.get("control_type") or ("number" if parameter["data_type"] == "number" else "text"),
                "display_style": configured.get("display_style") or "classic",
                "min_value": configured.get("min_value"),
                "max_value": configured.get("max_value"),
                "step_value": configured.get("step_value"),
                "placeholder": configured.get("placeholder") or "",
                "image_url": configured.get("image_url") or "",
                "value_image_mode": configured.get("value_image_mode") or "none",
                "is_required": configured.get("is_required", 0),
                "options": options_by_name.get(parameter["name"], []),
            })

        return jsonify({"schema": schema, "controls": controls})

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
        include_meta = _include_meta_flag(payload)
        deployed = _load_deployed_ruleset(conn, environment)
        ruleset = deployed["rules"]
        evaluated = evaluate_rules(ruleset, configuration)
        public_violations, violation_codes, violations_debug = _serialize_violations(evaluated.violations)
        _log_constraint_violations(
            violations_debug,
            context={
                "environment": str(environment),
                "customer_id": str(customer_id),
                "ruleset_id": deployed.get("ruleset_id"),
                "product_name": str(deployed["product_name"]),
                "category": str(deployed["category"]),
                "subcategory": str(deployed["subcategory"]),
                "version": deployed.get("version"),
            },
        )
        memo_schema = _build_configuration_memo_schema(ruleset, deployed)

        response = {
            "valid": evaluated.valid,
            "calculations": evaluated.calculations,
            "violations": public_violations,
            "violation_codes": violation_codes,
            "resolved_configuration": evaluated.resolved_configuration,
            "configuration_memo": {
                "schema": memo_schema,
                "inputs": configuration,
                "resolved": evaluated.resolved_configuration,
                "intermediate": evaluated.calculations,
            },
        }

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO configuration_memos(
                    customer_id,
                    environment,
                    ruleset_id,
                    product_name,
                    category,
                    subcategory,
                    version,
                    status,
                    memo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    customer_id,
                    environment,
                    deployed["ruleset_id"],
                    deployed["product_name"],
                    deployed["category"],
                    deployed["subcategory"],
                    deployed["version"],
                    "draft",
                    json_dumps(response["configuration_memo"]),
                ),
            )
            memo_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO configuration_states(customer_id, environment, state) VALUES (?, ?, ?)",
                (customer_id, environment, json_dumps(evaluated.resolved_configuration)),
            )

        _log_configuration_state_change(
            app,
            source="configurator.evaluate",
            customer_id=str(customer_id),
            environment=str(environment),
            state=evaluated.resolved_configuration,
        )

        response["configuration_memo"]["id"] = memo_id
        if include_meta:
            response["violations_debug"] = violations_debug
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

        deployed = _load_deployed_ruleset(conn, environment)
        specification = payload.get("specification", {})
        with conn:
            conn.execute(
                "INSERT INTO specifications(customer_id, environment, specification) VALUES (?, ?, ?)",
                (customer_id, environment, json_dumps(specification)),
            )
            conn.execute(
                """
                INSERT INTO configuration_memos(
                    customer_id,
                    environment,
                    ruleset_id,
                    product_name,
                    category,
                    subcategory,
                    version,
                    status,
                    memo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    customer_id,
                    environment,
                    deployed["ruleset_id"],
                    deployed["product_name"],
                    deployed["category"],
                    deployed["subcategory"],
                    deployed["version"],
                    "submitted",
                    json_dumps({"specification": specification}),
                ),
            )
        app.logger.info(
            "configuration_submitted",
            extra={"customer_id": customer_id, "environment": environment, "ruleset_id": deployed["ruleset_id"]},
        )
        return jsonify({"status": "submitted"})

    return app


def create_experience_studio_app(database_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    _configure_observability(app, "experience")
    _configure_error_handlers(app)
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.before_request
    def require_editor_role() -> Any:
        if request.endpoint in {"login", "logout", "static"}:
            return None
        if _is_frontend_editor():
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "frontend editor role required"}), 403
        return "Forbidden", 403

    @app.get("/")
    def index() -> str:
        return render_template("front_end_editor/index.html")

    @app.get("/api/mappings")
    def mappings() -> Any:
        ruleset_id = request.args.get("ruleset_id", type=int)
        conn = connect(_db_path(app))
        if not ruleset_id:
            latest = conn.execute("SELECT id FROM rulesets ORDER BY id DESC LIMIT 1").fetchone()
            ruleset_id = int(latest["id"]) if latest else 0

        rows = conn.execute(
            """
            SELECT id, parameter_name, ruleset_id, display_label, help_text, control_type, display_style,
                   min_value, max_value, step_value, placeholder, image_url, value_image_mode, is_required, schema_version
            FROM ui_parameter_configs
            WHERE ruleset_id = ?
            ORDER BY parameter_name
            """,
            (ruleset_id,),
        ).fetchall()
        option_rows = conn.execute(
            """
            SELECT id, parameter_name, ruleset_id, option_value, option_label, option_order, image_url
            FROM ui_parameter_options
            WHERE ruleset_id = ?
            ORDER BY parameter_name, option_order, id
            """,
            (ruleset_id,),
        ).fetchall()
        profiles = conn.execute(
            """
            SELECT parameter_name, data_type, parameter_class, governance_control_types
            FROM ruleset_parameter_profiles
            WHERE ruleset_id = ?
            ORDER BY parameter_name
            """,
            (ruleset_id,),
        ).fetchall()

        options_by_name: dict[str, list[dict[str, Any]]] = {}
        for row in option_rows:
            options_by_name.setdefault(row["parameter_name"], []).append(dict(row))

        governance = {
            row["parameter_name"]: {
                "data_type": row["data_type"],
                "parameter_class": row["parameter_class"],
                "allowed_controls": json.loads(row["governance_control_types"])["allowed"],
            }
            for row in profiles
        }

        return jsonify(
            {
                "ruleset_id": ruleset_id,
                "governance": governance,
                "mappings": [
                    {**dict(row), "options": options_by_name.get(row["parameter_name"], [])}
                    for row in rows
                ],
            }
        )

    @app.post("/api/mappings")
    def save_mapping() -> Any:
        body = _json_body()
        parameter_name = str(body.get("parameter_name", "")).strip()
        ruleset_id = int(body.get("ruleset_id", 0))
        if not parameter_name:
            return jsonify({"error": "parameter_name is required"}), 400
        if not ruleset_id:
            return jsonify({"error": "ruleset_id is required"}), 400

        conn = connect(_db_path(app))
        profile = conn.execute(
            """
            SELECT governance_control_types
            FROM ruleset_parameter_profiles
            WHERE ruleset_id = ? AND parameter_name = ?
            """,
            (ruleset_id, parameter_name),
        ).fetchone()
        if not profile:
            return jsonify({"error": "parameter is not available in this ruleset"}), 400

        allowed_controls = json.loads(profile["governance_control_types"])["allowed"]
        selected_control = str(body.get("control_type", "text")).strip()
        if selected_control not in allowed_controls:
            return (
                jsonify(
                    {
                        "error": "control_type is not allowed by governance",
                        "allowed_controls": allowed_controls,
                    }
                ),
                400,
            )

        with conn:
            current = conn.execute(
                "SELECT MAX(schema_version) AS current_version FROM ui_parameter_configs WHERE ruleset_id = ?",
                (ruleset_id,),
            ).fetchone()
            next_version = int(current["current_version"] or 0) + 1
            conn.execute(
                """
                INSERT INTO ui_parameter_configs(
                    parameter_name, ruleset_id, display_label, help_text, control_type, display_style,
                    min_value, max_value, step_value, placeholder, image_url, value_image_mode, is_required, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(parameter_name, ruleset_id) DO UPDATE SET
                    display_label = excluded.display_label,
                    help_text = excluded.help_text,
                    control_type = excluded.control_type,
                    display_style = excluded.display_style,
                    min_value = excluded.min_value,
                    max_value = excluded.max_value,
                    step_value = excluded.step_value,
                    placeholder = excluded.placeholder,
                    image_url = excluded.image_url,
                    value_image_mode = excluded.value_image_mode,
                    is_required = excluded.is_required,
                    schema_version = excluded.schema_version,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    parameter_name,
                    ruleset_id,
                    str(body.get("display_label", "")).strip() or parameter_name,
                    str(body.get("help_text", "")).strip(),
                    selected_control,
                    str(body.get("display_style", "classic")).strip(),
                    body.get("min_value"),
                    body.get("max_value"),
                    body.get("step_value"),
                    str(body.get("placeholder", "")).strip(),
                    str(body.get("image_url", "")).strip(),
                    str(body.get("value_image_mode", "none")).strip(),
                    1 if bool(body.get("is_required")) else 0,
                    next_version,
                ),
            )
            conn.execute(
                "DELETE FROM ui_parameter_options WHERE parameter_name = ? AND ruleset_id = ?",
                (parameter_name, ruleset_id),
            )
            option_rows = []
            for index, option in enumerate(body.get("options", [])):
                option_rows.append(
                    (
                        parameter_name,
                        ruleset_id,
                        str(option.get("value", "")).strip(),
                        str(option.get("label", "")).strip() or str(option.get("value", "")).strip(),
                        int(option.get("order", index + 1)),
                        str(option.get("image_url", "")).strip(),
                    )
                )
            if option_rows:
                conn.executemany(
                    """
                    INSERT INTO ui_parameter_options(parameter_name, ruleset_id, option_value, option_label, option_order, image_url)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    option_rows,
                )

            conn.execute(
                """
                INSERT INTO ui_schema_history(ruleset_id, schema_version, change_notes, updated_by)
                VALUES (?, ?, ?, ?)
                """,
                (
                    ruleset_id,
                    next_version,
                    str(body.get("change_notes", "Studio mapping update")).strip() or "Studio mapping update",
                    session.get("username", "ux-admin"),
                ),
            )
            conn.execute(
                """
                UPDATE release_workflows
                SET requires_ux_update = 0,
                    state = CASE WHEN state = 'draft' THEN 'in_studio' ELSE state END,
                    ux_schema_version = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE ruleset_id = ?
                """,
                (next_version, ruleset_id),
            )
        app.logger.info(
            "studio_mapping_saved",
            extra={"ruleset_id": ruleset_id, "parameter_name": parameter_name, "schema_version": next_version},
        )
        return jsonify({"status": "ok", "schema_version": next_version})

    @app.get("/api/schema-history")
    def schema_history() -> Any:
        ruleset_id = request.args.get("ruleset_id", type=int)
        if not ruleset_id:
            return jsonify({"error": "ruleset_id is required"}), 400
        conn = connect(_db_path(app))
        rows = conn.execute(
            """
            SELECT schema_version, change_notes, updated_by, created_at
            FROM ui_schema_history
            WHERE ruleset_id = ?
            ORDER BY schema_version DESC, id DESC
            """,
            (ruleset_id,),
        ).fetchall()
        return jsonify({"history": [dict(row) for row in rows]})

    return app
