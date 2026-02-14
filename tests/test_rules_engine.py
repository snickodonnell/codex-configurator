from sales_configurator.rules_engine import evaluate_rules, normalize_ruleset, optimize_configuration, safe_eval


def test_safe_eval_blocks_unsafe_calls() -> None:
    try:
        safe_eval("__import__('os').system('echo bad')", {})
    except ValueError:
        assert True
    else:
        raise AssertionError("unsafe expression should fail")


def test_evaluate_rules_success() -> None:
    ruleset = {
        "constraints": [{"expression": "quantity > 0", "message": "positive only"}],
        "calculations": [{"name": "total", "formula": "quantity * unit_price"}],
    }
    result = evaluate_rules(ruleset, {"quantity": 2, "unit_price": 10})
    assert result.valid is True
    assert result.calculations["total"] == 20


def test_optimize_configuration() -> None:
    ruleset = {
        "constraints": [{"expression": "x + y <= 4", "message": "capacity"}],
        "calculations": [{"name": "cost", "formula": "3*x + y"}],
    }
    result = optimize_configuration(
        domains={"x": [0, 1, 2], "y": [0, 1, 2, 3]},
        objective="cost",
        ruleset=ruleset,
        maximize=False,
    )
    assert result["objective_score"] == 0


def test_apply_static_default_value() -> None:
    ruleset = {
        "default_values": [{"name": "discount", "mode": "static", "value": 0.1}],
        "constraints": [{"expression": "discount <= 0.2", "message": "too high"}],
        "calculations": [{"name": "net", "formula": "base_price * (1-discount)"}],
    }
    result = evaluate_rules(ruleset, {"base_price": 100})
    assert result.valid is True
    assert result.resolved_configuration["discount"] == 0.1
    assert result.calculations["net"] == 90.0


def test_apply_dynamic_default_value() -> None:
    ruleset = {
        "default_values": [
            {
                "name": "discount",
                "mode": "dynamic",
                "rules": [
                    {"condition": "quantity >= 10", "value": 0.2},
                    {"formula": "0.05"},
                ],
            }
        ],
        "constraints": [{"expression": "discount <= 0.2", "message": "too high"}],
        "calculations": [{"name": "total", "formula": "quantity * base_price * (1-discount)"}],
    }
    result = evaluate_rules(ruleset, {"quantity": 12, "base_price": 10})
    assert result.valid is True
    assert result.resolved_configuration["discount"] == 0.2
    assert result.calculations["total"] == 96.0


def test_explicit_value_overrides_default() -> None:
    ruleset = {
        "default_values": [{"name": "discount", "mode": "static", "value": 0.1}],
        "constraints": [{"expression": "discount == 0", "message": "discount must be explicit"}],
        "calculations": [],
    }
    result = evaluate_rules(ruleset, {"discount": 0})
    assert result.valid is True
    assert result.resolved_configuration["discount"] == 0


def test_normalize_ruleset_for_compatibility() -> None:
    normalized = normalize_ruleset({"constraints": [{"expression": "x > 0", "message": "bad"}], "custom": True})
    assert normalized["schema_version"] == 1
    assert normalized["constraints"][0]["expression"] == "x > 0"
    assert normalized["calculations"] == []
    assert normalized["default_values"] == []
    assert normalized["custom"] is True
