import pytest

from sales_configurator.rules_engine import (
    RuleEngine,
    RulesParseError,
    UnsafeExpressionError,
    compile_expression,
    evaluate_program,
    evaluate_rules,
    infer_memo_parameters,
    extract_expression_variables,
    normalize_ruleset,
    optimize_configuration,
    parse_ruleset_pseudocode,
    register_custom_function,
    ruleset_to_pseudocode,
    safe_eval,
)


def test_safe_eval_blocks_unsafe_calls() -> None:
    with pytest.raises(UnsafeExpressionError):
        safe_eval("__import__('os').system('echo bad')", {})


def test_compile_expression_reusable_program() -> None:
    program = compile_expression("base_price * quantity")
    assert evaluate_program(program, {"base_price": 9, "quantity": 2}) == 18
    assert evaluate_program(program, {"base_price": 11, "quantity": 3}) == 33


def test_safe_eval_supports_allowed_math_functions() -> None:
    result = safe_eval("round(sqrt(total), 2)", {"total": 20})
    assert result == 4.47


def test_custom_function_registration() -> None:
    register_custom_function("double", lambda value: value * 2)
    assert safe_eval("double(x)", {"x": 6}) == 12


def test_ruleset_custom_function_can_be_used_in_calculation() -> None:
    ruleset = {
        "custom_functions": [{"name": "margin", "args": ["price", "cost"], "expression": "price - cost"}],
        "constraints": [],
        "calculations": [{"name": "profit", "formula": "margin(price, cost) * quantity"}],
    }
    result = evaluate_rules(ruleset, {"price": 100, "cost": 65, "quantity": 2})
    assert result.calculations["profit"] == 70.0


def test_ruleset_custom_function_wrong_arity_raises() -> None:
    ruleset = {
        "custom_functions": [{"name": "margin", "args": ["price", "cost"], "expression": "price - cost"}],
        "constraints": [],
        "calculations": [{"name": "profit", "formula": "margin(price)"}],
    }
    with pytest.raises(ValueError, match="expected 2 args"):
        evaluate_rules(ruleset, {"price": 10, "cost": 4})


def test_evaluate_rules_success() -> None:
    ruleset = {
        "constraints": [{"expression": "quantity > 0", "message": "positive only"}],
        "calculations": [{"name": "total", "formula": "quantity * unit_price"}],
    }
    result = evaluate_rules(ruleset, {"quantity": 2, "unit_price": 10})
    assert result.valid is True
    assert result.calculations["total"] == 20


def test_evaluate_rules_with_constraint_violation() -> None:
    ruleset = {
        "constraints": [
            {"expression": "quantity >= 1", "reason_code": "ERR_QUANTITY_REQUIRED"},
            {"expression": "discount <= 0.2", "reason_code": "ERR_DISCOUNT_HIGH"},
        ],
        "calculations": [{"name": "total", "formula": "quantity * unit_price"}],
    }
    result = evaluate_rules(ruleset, {"quantity": 0, "unit_price": 20, "discount": 0.5})
    assert result.valid is False
    assert [violation.code for violation in result.violations] == ["ERR_QUANTITY_REQUIRED", "ERR_DISCOUNT_HIGH"]
    assert result.violations[0].recommended_severity == "BLOCK"
    assert result.violations[0].meta["expression_raw"] == "quantity >= 1"


def test_optimize_configuration_minimize_and_keep_resolved_defaults() -> None:
    ruleset = {
        "default_values": [{"name": "shipping_fee", "mode": "static", "value": 5}],
        "constraints": [{"expression": "x + y <= 4", "message": "capacity"}],
        "calculations": [{"name": "cost", "formula": "3*x + y + shipping_fee"}],
    }
    result = optimize_configuration(
        domains={"x": [0, 1, 2], "y": [0, 1, 2, 3]},
        objective="cost",
        ruleset=ruleset,
        maximize=False,
    )
    assert result["objective_score"] == 5
    assert result["shipping_fee"] == 5


def test_optimize_configuration_maximize() -> None:
    ruleset = {
        "constraints": [{"expression": "qty <= 3", "message": "qty limit"}],
        "calculations": [{"name": "revenue", "formula": "qty * price"}],
    }
    result = optimize_configuration(
        domains={"qty": [1, 2, 3], "price": [10, 20]},
        objective="revenue",
        ruleset=ruleset,
        maximize=True,
    )
    assert result["objective_score"] == 60


def test_optimize_configuration_no_valid_solution_raises() -> None:
    ruleset = {"constraints": [{"expression": "x > 100", "message": "bad"}], "calculations": []}
    with pytest.raises(ValueError, match="No valid configuration"):
        optimize_configuration(domains={"x": [1, 2, 3]}, objective="x", ruleset=ruleset)


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


def test_apply_dynamic_default_value_with_fallback_formula() -> None:
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
    result = evaluate_rules(ruleset, {"quantity": 2, "base_price": 10})
    assert result.valid is True
    assert result.resolved_configuration["discount"] == 0.05
    assert result.calculations["total"] == 19.0


def test_dynamic_default_without_matching_rule_raises() -> None:
    ruleset = {
        "default_values": [
            {
                "name": "discount",
                "mode": "dynamic",
                "rules": [{"condition": "quantity > 10", "value": 0.2}],
            }
        ],
        "constraints": [],
        "calculations": [],
    }
    with pytest.raises(ValueError, match="no dynamic default matched"):
        evaluate_rules(ruleset, {"quantity": 1})


def test_explicit_value_overrides_default() -> None:
    ruleset = {
        "default_values": [{"name": "discount", "mode": "static", "value": 0.1}],
        "constraints": [{"expression": "discount == 0", "message": "discount must be explicit"}],
        "calculations": [],
    }
    result = evaluate_rules(ruleset, {"discount": 0})
    assert result.valid is True
    assert result.resolved_configuration["discount"] == 0


def test_invalid_default_mode_raises() -> None:
    ruleset = {
        "default_values": [{"name": "discount", "mode": "computed", "value": 0.1}],
        "constraints": [],
        "calculations": [],
    }
    with pytest.raises(ValueError, match="unsupported default mode"):
        evaluate_rules(ruleset, {})




def test_infer_memo_parameters_includes_inputs_optional_and_intermediate() -> None:
    ruleset = {
        "constraints": [{"expression": "quantity >= 1 and region == 'NA'", "message": "bad"}],
        "default_values": [{"name": "discount", "mode": "static", "value": 0.1}],
        "calculations": [{"name": "total", "formula": "quantity * base_price * (1-discount)"}],
    }
    memo_params = infer_memo_parameters(ruleset)
    classes = {item["name"]: item["parameter_class"] for item in memo_params}

    assert classes["quantity"] == "required_input"
    assert classes["base_price"] == "required_input"
    assert classes["region"] == "required_input"
    assert classes["discount"] == "optional_input"
    assert classes["total"] == "intermediate"


def test_normalize_ruleset_for_compatibility() -> None:
    normalized = normalize_ruleset({"constraints": [{"expression": "x > 0", "message": "bad"}], "memo_parameters": [{"name": "x"}], "custom": True})
    assert normalized["schema_version"] == 1
    assert normalized["constraints"][0]["expression"] == "x > 0"
    assert normalized["calculations"] == []
    assert normalized["default_values"] == []
    assert normalized["memo_parameters"][0]["name"] == "x"
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
    assert parsed["constraints"][0]["reason_code"] == "Quantity must be at least 1"
    assert parsed["calculations"][0]["name"] == "total"
    assert parsed["custom_functions"][0]["name"] == "margin"


def test_parse_ruleset_pseudocode_reports_invalid_line() -> None:
    with pytest.raises(RulesParseError, match="unrecognized statement"):
        parse_ruleset_pseudocode("BROKEN something")


def test_parse_ruleset_pseudocode_dynamic_formula_default() -> None:
    parsed = parse_ruleset_pseudocode("DEFAULT discount = base_discount * 0.5")
    assert parsed["default_values"][0]["mode"] == "dynamic"
    assert parsed["default_values"][0]["rules"][0]["formula"] == "base_discount * 0.5"


def test_ruleset_to_pseudocode_round_trip() -> None:
    ruleset = {
        "default_values": [{"name": "discount", "mode": "static", "value": 0.1}],
        "constraints": [{"expression": "quantity >= 1", "reason_code": "ERR_BAD_QTY"}],
        "calculations": [{"name": "total", "formula": "base_price * quantity"}],
    }
    pseudo = ruleset_to_pseudocode(ruleset)
    assert "DEFAULT discount = 0.1" in pseudo
    assert "CONSTRAINT quantity >= 1 :: ERR_BAD_QTY" in pseudo


def test_rule_engine_can_be_reused_for_multiple_evaluations() -> None:
    ruleset = {
        "constraints": [{"expression": "quantity >= 1", "message": "quantity"}],
        "calculations": [{"name": "total", "formula": "quantity * unit_price"}],
    }
    engine = RuleEngine.from_ruleset(ruleset)

    first = engine.evaluate({"quantity": 1, "unit_price": 9})
    second = engine.evaluate({"quantity": 2, "unit_price": 9})

    assert first.calculations["total"] == 9
    assert second.calculations["total"] == 18


def test_parse_ruleset_pseudocode_constraint_default_reason_code() -> None:
    parsed = parse_ruleset_pseudocode("CONSTRAINT quantity >= 1")
    assert parsed["constraints"][0]["reason_code"] == "ERR_CONSTRAINT_FAILED"


def test_extract_expression_variables_for_constraint_metadata() -> None:
    variables = extract_expression_variables("quantity >= min_qty and discount <= max_discount")
    assert variables == {"quantity", "min_qty", "discount", "max_discount"}
