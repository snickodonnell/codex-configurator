import json

from sales_configurator.app import create_configurator_app, create_landing_app, create_rules_engine_app
from sales_configurator.db import connect


def login(client) -> None:
    response = client.post("/login", data={"username": "admin", "password": "admin"})
    assert response.status_code == 302


def seed_ruleset(rules_client, payload: str, name: str = "test") -> None:
    response = rules_client.post(
        "/rulesets",
        data={
            "name": name,
            "environment": "dev",
            "product_name": "laptop",
            "category": "pricing",
            "subcategory": "discounts",
            "version": "1",
            "payload": payload,
        },
    )
    assert response.status_code == 302


def test_auth_required(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_configurator_app(str(db))
    client = app.test_client()

    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.location

    api_response = client.post("/api/evaluate", json={})
    assert api_response.status_code == 401


def test_login_rejects_invalid_credentials(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_landing_app(str(db))
    client = app.test_client()

    response = client.post("/login", data={"username": "wrong", "password": "nope"})
    assert response.status_code == 200
    assert "Invalid credentials" in response.get_data(as_text=True)


def test_logout_clears_session(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_landing_app(str(db))
    client = app.test_client()
    login(client)

    response = client.post("/logout")
    assert response.status_code == 302

    redirected = client.get("/")
    assert redirected.status_code == 302
    assert "/login" in redirected.location


def test_landing_page_lists_portfolios(tmp_path) -> None:
    db = tmp_path / "app.db"
    rules = create_rules_engine_app(str(db))
    rules_client = rules.test_client()
    login(rules_client)
    seed_ruleset(
        rules_client,
        '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
        name="Laptop Rules",
    )

    configurator = create_configurator_app(str(db))
    config_client = configurator.test_client()
    login(config_client)
    config_client.post(
        "/api/evaluate",
        json={
            "customer_id": "demo-customer",
            "api_key": "demo-key",
            "environment": "dev",
            "configuration": {"quantity": 2, "base_price": 15, "discount": 0.1, "region": "NA"},
        },
    )

    landing = create_landing_app(str(db))
    landing_client = landing.test_client()
    login(landing_client)

    add = landing_client.post(
        "/enhancements",
        data={"title": "Add sidebar", "status": "in-progress", "notes": "Improved navigation"},
    )
    assert add.status_code == 302

    page = landing_client.get("/")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "Laptop Rules" in html
    assert "Add sidebar" in html
    assert "demo-customer" in html


def test_ruleset_create_and_deploy(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_rules_engine_app(str(db))
    client = app.test_client()
    login(client)

    seed_ruleset(
        client,
        '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
    )

    edit_page = client.get("/?edit=1")
    assert edit_page.status_code == 200
    assert "pricing" in edit_page.get_data(as_text=True)

    update = client.post(
        "/rulesets",
        data={
            "ruleset_id": "1",
            "name": "test-updated",
            "environment": "dev",
            "product_name": "laptop",
            "category": "pricing",
            "subcategory": "discounts",
            "version": "2",
            "payload": '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
        },
    )
    assert update.status_code == 302

    response = client.post("/deploy/1", data={"environment": "dev"})
    assert response.status_code == 302


def test_ruleset_create_invalid_payload_redirects_with_error(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_rules_engine_app(str(db))
    client = app.test_client()
    login(client)

    response = client.post(
        "/rulesets",
        data={
            "name": "bad-rules",
            "environment": "dev",
            "payload": "{this is invalid",
        },
    )
    assert response.status_code == 302
    assert "error=" in response.location


def test_ruleset_create_from_pseudocode(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_rules_engine_app(str(db))
    client = app.test_client()
    login(client)

    response = client.post(
        "/rulesets",
        data={
            "name": "dsl-rules",
            "environment": "dev",
            "product_name": "desktop",
            "category": "availability",
            "subcategory": "stock",
            "version": "1",
            "pseudo_rules": "DEFAULT discount = 0.05\nCONSTRAINT quantity >= 1 :: Quantity required\nCALC total = base_price * quantity * (1-discount)",
        },
    )
    assert response.status_code == 302

    page = client.get("/")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "dsl-rules" in html
    assert "availability" in html




def test_configuration_memo_schema_endpoint(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_configurator_app(str(db))
    client = app.test_client()
    login(client)

    response = client.get("/api/configuration-memo?environment=dev")
    assert response.status_code == 200
    body = response.get_json()
    assert body["product_name"] == "default-product"
    assert any(param["name"] == "quantity" for param in body["required_input"])
    assert any(param["parameter_class"] == "intermediate" for param in body["intermediate"])


def test_evaluate_and_submit(tmp_path) -> None:
    db = tmp_path / "app.db"
    rules = create_rules_engine_app(str(db))
    rules_client = rules.test_client()
    login(rules_client)

    seed_ruleset(
        rules_client,
        '{"default_values":[{"name":"discount","mode":"static","value":0}],"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[{"name":"total","formula":"quantity*base_price*(1-discount)"}]}',
    )
    rules_client.post("/deploy/1", data={"environment": "dev"})

    app = create_configurator_app(str(db))
    client = app.test_client()
    login(client)

    evaluate = client.post(
        "/api/evaluate",
        json={
            "customer_id": "demo-customer",
            "api_key": "demo-key",
            "environment": "dev",
            "configuration": {"quantity": 2, "base_price": 15},
        },
    )
    assert evaluate.status_code == 200
    body = evaluate.get_json()
    assert body["resolved_configuration"]["discount"] == 0
    assert body["calculations"]["total"] == 30.0
    assert body["configuration_memo"]["schema"]["version"] == 1

    conn = connect(db)
    memo_row = conn.execute("SELECT status, memo FROM configuration_memos ORDER BY id DESC LIMIT 1").fetchone()
    assert memo_row["status"] == "draft"
    assert json.loads(memo_row["memo"])["resolved"]["discount"] == 0

    submit = client.post(
        "/api/submit",
        json={
            "customer_id": "demo-customer",
            "api_key": "demo-key",
            "environment": "dev",
            "specification": {"sku": "ABC", "quantity": 2},
        },
    )
    assert submit.status_code == 200
    assert submit.get_json()["status"] == "submitted"

    submitted_row = conn.execute("SELECT status FROM configuration_memos ORDER BY id DESC LIMIT 1").fetchone()
    assert submitted_row["status"] == "submitted"


def test_evaluate_forbidden_with_wrong_api_key(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_configurator_app(str(db))
    client = app.test_client()
    login(client)

    evaluate = client.post(
        "/api/evaluate",
        json={
            "customer_id": "demo-customer",
            "api_key": "wrong",
            "environment": "dev",
            "configuration": {"quantity": 1, "base_price": 5},
        },
    )
    assert evaluate.status_code == 403


def test_evaluate_uses_default_ruleset_when_nothing_deployed(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_configurator_app(str(db))
    client = app.test_client()
    login(client)

    evaluate = client.post(
        "/api/evaluate",
        json={
            "customer_id": "demo-customer",
            "api_key": "demo-key",
            "environment": "dev",
            "configuration": {"quantity": 2, "base_price": 10, "discount": 0.1, "region": "NA"},
        },
    )
    assert evaluate.status_code == 200
    assert evaluate.get_json()["calculations"]["total_price"] == 18.0


def test_optimize_endpoint(tmp_path) -> None:
    db = tmp_path / "app.db"
    rules = create_rules_engine_app(str(db))
    client = rules.test_client()
    login(client)
    seed_ruleset(
        client,
        '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[{"name":"total_price","formula":"quantity*base_price*(1-discount)"}]}',
    )
    client.post("/deploy/1", data={"environment": "dev"})

    response = client.post(
        "/optimize",
        json={
            "environment": "dev",
            "domains": {"quantity": [1, 2], "base_price": [100], "discount": [0, 0.1]},
            "objective": "total_price",
            "maximize": False,
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["objective_score"] == 90.0


def test_evaluate_persists_configuration_state(tmp_path) -> None:
    db = tmp_path / "app.db"
    rules = create_rules_engine_app(str(db))
    rules_client = rules.test_client()
    login(rules_client)
    seed_ruleset(
        rules_client,
        '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
    )
    rules_client.post("/deploy/1", data={"environment": "dev"})

    app = create_configurator_app(str(db))
    client = app.test_client()
    login(client)

    evaluate = client.post(
        "/api/evaluate",
        json={
            "customer_id": "demo-customer",
            "api_key": "demo-key",
            "environment": "dev",
            "configuration": {"quantity": 2, "base_price": 15, "discount": 0.1, "region": "NA"},
        },
    )
    assert evaluate.status_code == 200

    conn = connect(db)
    row = conn.execute(
        "SELECT customer_id, environment, state FROM configuration_states ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["customer_id"] == "demo-customer"
    assert row["environment"] == "dev"
    assert json.loads(row["state"])["quantity"] == 2


def test_workspace_api_supports_product_switching_and_rule_editability(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_rules_engine_app(str(db))
    client = app.test_client()
    login(client)

    created = client.post(
        "/api/workspace/products",
        json={"name": "Servers", "description": "Rack server rules"},
    )
    assert created.status_code == 201
    product_id = created.get_json()["id"]

    category = client.post(
        "/api/workspace/categories",
        json={"product_id": product_id, "name": "Availability", "position": 1},
    )
    assert category.status_code == 201
    category_id = category.get_json()["id"]

    rule = client.post(
        "/api/workspace/rules",
        json={
            "product_id": product_id,
            "category_id": category_id,
            "rule_type": "constraint",
            "expression": "quantity >= 2",
            "message": "Need at least two nodes",
            "position": 2,
        },
    )
    assert rule.status_code == 201
    rule_id = rule.get_json()["id"]

    toggle = client.post(f"/api/workspace/rules/{rule_id}/editable", json={"is_editable": True})
    assert toggle.status_code == 200

    workspace = client.get("/api/workspace")
    assert workspace.status_code == 200
    payload = workspace.get_json()
    server_product = next(product for product in payload["products"] if product["name"] == "Servers")
    fetched_rule = server_product["categories"][0]["rules"][0]
    assert fetched_rule["expression"] == "quantity >= 2"
    assert fetched_rule["is_editable"] == 1


def test_workspace_rule_position_update(tmp_path) -> None:
    db = tmp_path / "app.db"
    app = create_rules_engine_app(str(db))
    client = app.test_client()
    login(client)

    workspace = client.get("/api/workspace").get_json()
    product = workspace["products"][0]
    category = product["categories"][0]
    sub = category["subcategories"][0]

    created = client.post(
        "/api/workspace/rules",
        json={
            "product_id": product["id"],
            "category_id": category["id"],
            "subcategory_id": sub["id"],
            "rule_type": "constraint",
            "expression": "region == 'NA'",
            "message": "North America only",
            "position": 6,
        },
    )
    assert created.status_code == 201
    rule_id = created.get_json()["id"]

    moved = client.post(f"/api/workspace/rules/{rule_id}/position", json={"position": 1})
    assert moved.status_code == 200

    refreshed = client.get("/api/workspace").get_json()
    product_after = next(item for item in refreshed["products"] if item["id"] == product["id"])
    sub_after = product_after["categories"][0]["subcategories"][0]
    created_rule = next(item for item in sub_after["rules"] if item["id"] == rule_id)
    assert created_rule["position"] == 1
