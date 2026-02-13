from sales_configurator.rules_engine import evaluate_rules, optimize_configuration, safe_eval


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
