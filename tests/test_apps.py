from sales_configurator.app import create_configurator_app, create_landing_app, create_rules_engine_app


def login(client) -> None:
    response = client.post("/login", data={"username": "admin", "password": "admin"})
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


def test_landing_page_lists_portfolios(tmp_path) -> None:
    db = tmp_path / "app.db"
    rules = create_rules_engine_app(str(db))
    rules_client = rules.test_client()
    login(rules_client)
    rules_client.post(
        "/rulesets",
        data={
            "name": "Laptop Rules",
            "environment": "dev",
            "payload": '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
        },
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

    response = client.post(
        "/rulesets",
        data={
            "name": "test",
            "environment": "dev",
            "product_name": "laptop",
            "category": "pricing",
            "subcategory": "discounts",
            "version": "1",
            "payload": '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
        },
    )
    assert response.status_code == 302

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


def test_evaluate_and_submit(tmp_path) -> None:
    db = tmp_path / "app.db"
    rules = create_rules_engine_app(str(db))
    rules_client = rules.test_client()
    login(rules_client)

    rules_client.post(
        "/rulesets",
        data={
            "name": "test",
            "environment": "dev",
            "payload": '{"default_values":[{"name":"discount","mode":"static","value":0}],"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[{"name":"total","formula":"quantity*base_price*(1-discount)"}]}',
        },
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
