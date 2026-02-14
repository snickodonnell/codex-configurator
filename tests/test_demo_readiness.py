from sales_configurator.app import (
    create_configurator_app,
    create_experience_studio_app,
    create_landing_app,
    create_rules_engine_app,
)


def _login_admin(client) -> None:
    response = client.post("/login", data={"username": "admin", "password": "admin"})
    assert response.status_code == 302


def _login_ux(client) -> None:
    response = client.post("/login", data={"username": "ux-admin", "password": "ux-admin"})
    assert response.status_code == 302


def test_health_endpoint_available_without_auth_for_all_apps(tmp_path) -> None:
    db = tmp_path / "app.db"
    apps = [
        create_landing_app(str(db)),
        create_rules_engine_app(str(db)),
        create_configurator_app(str(db)),
        create_experience_studio_app(str(db)),
    ]

    for app in apps:
        response = app.test_client().get("/healthz")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "ok"
        assert payload["app"] in {"landing", "rules", "configurator", "experience"}


def test_demo_journey_rules_to_studio_to_customer_runtime(tmp_path) -> None:
    db = tmp_path / "app.db"

    rules_client = create_rules_engine_app(str(db)).test_client()
    _login_admin(rules_client)
    response = rules_client.post(
        "/rulesets",
        data={
            "name": "Demo Rule Journey",
            "environment": "dev",
            "product_name": "laptop",
            "category": "pricing",
            "subcategory": "discount",
            "version": "1",
            "pseudo_rules": "\n".join(
                [
                    "DEFAULT discount = 0.1",
                    "CONSTRAINT quantity >= 1 :: ERR_QTY_REQUIRED",
                    "CALC total_price = quantity * base_price * (1 - discount)",
                ]
            ),
        },
    )
    assert response.status_code == 302

    assert rules_client.post("/workflow/1/send-to-studio").status_code == 302

    studio_client = create_experience_studio_app(str(db)).test_client()
    _login_ux(studio_client)

    for parameter_name, control_type, label in [
        ("quantity", "slider", "Quantity"),
        ("base_price", "number", "Base Price"),
        ("discount", "slider", "Discount"),
    ]:
        map_response = studio_client.post(
            "/api/mappings",
            json={
                "ruleset_id": 1,
                "parameter_name": parameter_name,
                "control_type": control_type,
                "display_label": label,
            },
        )
        assert map_response.status_code == 200

    assert rules_client.post("/workflow/1/request-approval").status_code == 302
    assert rules_client.post("/workflow/1/approve").status_code == 302
    assert rules_client.post("/deploy/1", data={"environment": "dev"}).status_code == 302

    configurator_client = create_configurator_app(str(db)).test_client()
    _login_admin(configurator_client)

    schema_response = configurator_client.get("/api/ui-schema?environment=dev")
    assert schema_response.status_code == 200
    schema_payload = schema_response.get_json()
    parameter_names = {item["parameter_name"] for item in schema_payload["controls"]}
    assert {"quantity", "base_price", "discount"}.issubset(parameter_names)

    evaluate_response = configurator_client.post(
        "/api/evaluate",
        json={
            "customer_id": "demo-customer",
            "api_key": "demo-key",
            "environment": "dev",
            "configuration": {"quantity": 2, "base_price": 1000},
        },
    )
    assert evaluate_response.status_code == 200
    body = evaluate_response.get_json()
    assert body["valid"] is True
    assert body["calculations"]["total_price"] == 1800.0
