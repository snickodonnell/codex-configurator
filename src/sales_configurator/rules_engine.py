from __future__ import annotations

import ast
import itertools
import math
from dataclasses import dataclass
from typing import Any, Callable

ALLOWED_FUNCTIONS = {
    "abs": abs,
    "ceil": math.ceil,
    "floor": math.floor,
    "max": max,
    "min": min,
    "round": round,
    "sqrt": math.sqrt,
}

CUSTOM_FUNCTIONS: dict[str, Callable[..., Any]] = {}

ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.BinOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.And,
    ast.Or,
    ast.Not,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.Pow,
    ast.USub,
    ast.UAdd,
    ast.Eq,
    ast.NotEq,
    ast.Gt,
    ast.GtE,
    ast.Lt,
    ast.LtE,
    ast.Call,
)


class UnsafeExpressionError(ValueError):
    """Raised when the expression includes unsafe syntax."""


class RulesParseError(ValueError):
    """Raised when pseudo-code rules cannot be parsed."""


def register_custom_function(name: str, function: Callable[..., Any]) -> None:
    CUSTOM_FUNCTIONS[name] = function


def normalize_ruleset(ruleset: dict[str, Any] | None) -> dict[str, Any]:
    base = ruleset or {}
    return {
        "schema_version": int(base.get("schema_version", 1)),
        "default_values": list(base.get("default_values", [])),
        "constraints": list(base.get("constraints", [])),
        "calculations": list(base.get("calculations", [])),
        "custom_functions": list(base.get("custom_functions", [])),
        **{
            key: value
            for key, value in base.items()
            if key
            not in {"default_values", "constraints", "calculations", "schema_version", "custom_functions"}
        },
    }


def _resolve_eval_functions(extra_functions: dict[str, Callable[..., Any]] | None = None) -> dict[str, Callable[..., Any]]:
    functions = {**ALLOWED_FUNCTIONS, **CUSTOM_FUNCTIONS}
    if extra_functions:
        functions.update(extra_functions)
    return functions


def _validate_ast(tree: ast.AST, allowed_function_names: set[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise UnsafeExpressionError(f"Unsupported expression node: {type(node).__name__}")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in allowed_function_names:
                raise UnsafeExpressionError("Unsupported function call")


def safe_eval(
    expression: str,
    context: dict[str, Any],
    extra_functions: dict[str, Callable[..., Any]] | None = None,
) -> Any:
    functions = _resolve_eval_functions(extra_functions)
    tree = ast.parse(expression, mode="eval")
    _validate_ast(tree, set(functions))
    compiled = compile(tree, "<rules>", "eval")
    return eval(compiled, {"__builtins__": {}, **functions}, context)


def _parse_literal_or_expression(raw_value: str) -> tuple[str, Any]:
    text = raw_value.strip()
    try:
        parsed = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return "formula", text
    return "value", parsed


def parse_ruleset_pseudocode(pseudo_code: str) -> dict[str, Any]:
    ruleset: dict[str, Any] = {
        "schema_version": 1,
        "default_values": [],
        "constraints": [],
        "calculations": [],
        "custom_functions": [],
        "pseudo_code": pseudo_code.strip(),
    }

    for line_number, raw_line in enumerate(pseudo_code.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("DEFAULT "):
            body = line[len("DEFAULT ") :].strip()
            if "=" not in body:
                raise RulesParseError(f"line {line_number}: DEFAULT requires '='")
            before_equals, right_side = body.rsplit("=", 1)
            before_equals = before_equals.strip()
            right_side = right_side.strip()
            if " WHEN " in before_equals:
                name, condition = before_equals.split(" WHEN ", 1)
                name = name.strip()
                condition = condition.strip()
                value_kind, value = _parse_literal_or_expression(right_side)
                existing = next(
                    (item for item in ruleset["default_values"] if item["name"] == name and item.get("mode") == "dynamic"),
                    None,
                )
                if existing is None:
                    existing = {"name": name, "mode": "dynamic", "rules": []}
                    ruleset["default_values"].append(existing)
                existing_rule = {"condition": condition}
                existing_rule[value_kind] = value
                existing["rules"].append(existing_rule)
            else:
                name = before_equals
                value_kind, value = _parse_literal_or_expression(right_side)
                if value_kind == "formula":
                    ruleset["default_values"].append(
                        {"name": name, "mode": "dynamic", "rules": [{"formula": value}]}
                    )
                else:
                    ruleset["default_values"].append({"name": name, "mode": "static", "value": value})
            continue

        if line.startswith("CONSTRAINT "):
            body = line[len("CONSTRAINT ") :].strip()
            if "::" in body:
                expression, message = body.split("::", 1)
                message = message.strip()
            else:
                expression = body
                message = "Constraint failed"
            ruleset["constraints"].append({"expression": expression.strip(), "message": message})
            continue

        if line.startswith("CALC "):
            body = line[len("CALC ") :].strip()
            if "=" not in body:
                raise RulesParseError(f"line {line_number}: CALC requires '='")
            name, formula = body.split("=", 1)
            ruleset["calculations"].append({"name": name.strip(), "formula": formula.strip()})
            continue

        if line.startswith("FUNCTION "):
            body = line[len("FUNCTION ") :].strip()
            if "=" not in body:
                raise RulesParseError(f"line {line_number}: FUNCTION requires '='")
            signature, expression = body.split("=", 1)
            name, arglist = signature.split("(", 1)
            args = [arg.strip() for arg in arglist.rstrip(")").split(",") if arg.strip()]
            ruleset["custom_functions"].append(
                {"name": name.strip(), "args": args, "expression": expression.strip()}
            )
            continue

        raise RulesParseError(f"line {line_number}: unrecognized statement '{line}'")

    return ruleset


def ruleset_to_pseudocode(ruleset: dict[str, Any]) -> str:
    normalized = normalize_ruleset(ruleset)
    if normalized.get("pseudo_code"):
        return str(normalized["pseudo_code"])

    lines: list[str] = []
    for default in normalized["default_values"]:
        if default.get("mode") == "static":
            lines.append(f"DEFAULT {default['name']} = {repr(default['value'])}")
            continue
        for rule in default.get("rules", []):
            rhs = rule.get("formula")
            if rhs is None:
                rhs = repr(rule.get("value"))
            condition = rule.get("condition")
            if condition:
                lines.append(f"DEFAULT {default['name']} WHEN {condition} = {rhs}")
            else:
                lines.append(f"DEFAULT {default['name']} = {rhs}")

    for constraint in normalized["constraints"]:
        lines.append(f"CONSTRAINT {constraint['expression']} :: {constraint['message']}")

    for calc in normalized["calculations"]:
        lines.append(f"CALC {calc['name']} = {calc['formula']}")

    for func in normalized.get("custom_functions", []):
        args = ", ".join(func.get("args", []))
        lines.append(f"FUNCTION {func['name']}({args}) = {func['expression']}")

    return "\n".join(lines)


@dataclass(slots=True)
class EvaluationResult:
    valid: bool
    calculations: dict[str, float]
    violations: list[str]
    resolved_configuration: dict[str, Any]


def _resolve_default_value(default_entry: dict[str, Any], context: dict[str, Any]) -> Any:
    mode = default_entry.get("mode", "static")
    if mode == "static":
        if "value" not in default_entry:
            raise ValueError("static defaults must define a value")
        return default_entry["value"]

    if mode != "dynamic":
        raise ValueError(f"unsupported default mode: {mode}")

    rules = default_entry.get("rules", [])
    for rule in rules:
        condition = rule.get("condition")
        if condition is not None and not bool(safe_eval(condition, context)):
            continue
        if "formula" in rule:
            return safe_eval(rule["formula"], context)
        if "value" in rule:
            return rule["value"]
        raise ValueError("dynamic default rule must define value or formula")

    raise ValueError(f"no dynamic default matched for field: {default_entry.get('name', '<unknown>')}")


def apply_default_values(ruleset: dict[str, Any], configuration: dict[str, Any]) -> dict[str, Any]:
    resolved = {**configuration}
    for default_entry in ruleset.get("default_values", []):
        name = default_entry["name"]
        if name in resolved:
            continue
        resolved[name] = _resolve_default_value(default_entry, resolved)
    return resolved


def evaluate_rules(ruleset: dict[str, Any], configuration: dict[str, Any]) -> EvaluationResult:
    normalized = normalize_ruleset(ruleset)
    resolved_configuration = apply_default_values(normalized, configuration)
    violations: list[str] = []
    for constraint in normalized.get("constraints", []):
        result = safe_eval(constraint["expression"], resolved_configuration)
        if not bool(result):
            violations.append(constraint["message"])

    calculations: dict[str, float] = {}
    working_context = {**resolved_configuration}
    for calc in normalized.get("calculations", []):
        value = safe_eval(calc["formula"], working_context)
        calculations[calc["name"]] = float(value)
        working_context[calc["name"]] = value

    return EvaluationResult(
        valid=(len(violations) == 0),
        calculations=calculations,
        violations=violations,
        resolved_configuration=resolved_configuration,
    )


def optimize_configuration(
    domains: dict[str, list[Any]],
    objective: str,
    ruleset: dict[str, Any],
    maximize: bool = False,
) -> dict[str, Any]:
    keys = list(domains.keys())
    best_score = float("-inf") if maximize else float("inf")
    best_config: dict[str, Any] | None = None

    for values in itertools.product(*(domains[key] for key in keys)):
        candidate = dict(zip(keys, values, strict=True))
        evaluated = evaluate_rules(ruleset, candidate)
        if not evaluated.valid:
            continue
        score = float(safe_eval(objective, {**candidate, **evaluated.calculations}))
        is_better = score > best_score if maximize else score < best_score
        if is_better:
            best_score = score
            best_config = {**candidate, **evaluated.calculations, "objective_score": score}

    if best_config is None:
        raise ValueError("No valid configuration found for provided domains/rules")

    return best_config
