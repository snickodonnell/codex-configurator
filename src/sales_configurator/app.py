from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

from .db import connect, init_db, json_dumps
from .rules_engine import (
    RulesParseError,
    evaluate_rules,
    infer_memo_parameters,
    normalize_ruleset,
    optimize_configuration,
    parse_ruleset_pseudocode,
    ruleset_to_pseudocode,
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
    return session.get("username") == ADMIN_USERNAME and session.get("role") == "admin"


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
            conn.execute(
                f"DELETE FROM workspace_rules WHERE category_id = ? OR subcategory_id IN ({','.join('?' for _ in child_ids)})"
                if child_ids
                else "DELETE FROM workspace_rules WHERE category_id = ?",
                (category_id, *child_ids),
            )
            if child_ids:
                conn.execute(
                    f"DELETE FROM workspace_categories WHERE id IN ({','.join('?' for _ in child_ids)})",
                    child_ids,
                )
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
                        json_dumps(normalize_ruleset(parsed)),
                        int(ruleset_id),
                    ),
                )
            else:
                conn.execute(
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
                        json_dumps(normalize_ruleset(parsed)),
                    ),
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
    app.config["DATABASE_PATH"] = database_path or os.environ.get("RULES_DB_PATH", "./data.db")
    init_db(_db_path(app))
    _configure_auth(app)

    @app.get("/")
    def index() -> str:
        return render_template("configurator/index.html")

    @app.get("/api/configuration-memo")
    def configuration_memo() -> Any:
        environment = request.args.get("environment", "dev")
        conn = connect(_db_path(app))
        deployed = _load_deployed_ruleset(conn, environment)
        schema = _build_configuration_memo_schema(deployed["rules"], deployed)
        return jsonify(schema)

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
        deployed = _load_deployed_ruleset(conn, environment)
        ruleset = deployed["rules"]
        evaluated = evaluate_rules(ruleset, configuration)
        memo_schema = _build_configuration_memo_schema(ruleset, deployed)

        response = {
            "valid": evaluated.valid,
            "calculations": evaluated.calculations,
            "violations": evaluated.violations,
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

        response["configuration_memo"]["id"] = memo_id
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
        return jsonify({"status": "submitted"})

    return app
