from sales_configurator.rules_engine import (
    evaluate_rules,
    normalize_ruleset,
    optimize_configuration,
    parse_ruleset_pseudocode,
    ruleset_to_pseudocode,
    safe_eval,
)


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


def test_parse_ruleset_pseudocode() -> None:
    parsed = parse_ruleset_pseudocode(
        """
        DEFAULT discount = 0.05
        DEFAULT region WHEN country == 'DE' = 'EU'
        CONSTRAINT quantity >= 1 :: Quantity must be at least 1
        CALC total = base_price * quantity * (1-discount)
        FUNCTION margin(price,cost) = price-cost
        """
    )
    assert parsed["default_values"][0]["name"] == "discount"
    assert parsed["default_values"][1]["rules"][0]["condition"] == "country == 'DE'"
    assert parsed["constraints"][0]["message"] == "Quantity must be at least 1"
    assert parsed["calculations"][0]["name"] == "total"
    assert parsed["custom_functions"][0]["name"] == "margin"


def test_ruleset_to_pseudocode_round_trip() -> None:
    ruleset = {
        "default_values": [{"name": "discount", "mode": "static", "value": 0.1}],
        "constraints": [{"expression": "quantity >= 1", "message": "bad qty"}],
        "calculations": [{"name": "total", "formula": "base_price * quantity"}],
    }
    pseudo = ruleset_to_pseudocode(ruleset)
    assert "DEFAULT discount = 0.1" in pseudo
    assert "CONSTRAINT quantity >= 1 :: bad qty" in pseudo
