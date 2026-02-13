from sales_configurator.app import create_configurator_app, create_rules_engine_app


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
            "payload": '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[]}',
        },
    )
    assert response.status_code == 302

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
            "payload": '{"constraints":[{"expression":"quantity>=1","message":"x"}],"calculations":[{"name":"total","formula":"quantity*base_price"}]}',
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
    assert evaluate.get_json()["calculations"]["total"] == 30.0

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
