from __future__ import annotations

import ast
import itertools
import logging
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
DEFAULT_CONSTRAINT_REASON_CODE = "ERR_CONSTRAINT_FAILED"

logger = logging.getLogger(__name__)

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


@dataclass(slots=True, frozen=True)
class ExpressionProgram:
    """Validated, compiled expression that can be reused safely."""

    source: str
    code: Any


@dataclass(slots=True)
class EvaluationResult:
    valid: bool
    calculations: dict[str, float]
    violations: list[Violation]
    resolved_configuration: dict[str, Any]


@dataclass(slots=True)
class Violation:
    code: str
    recommended_severity: str
    meta: dict[str, Any]
    rule: dict[str, str]


@dataclass(slots=True)
class _CalculationSpec:
    name: str
    program: ExpressionProgram


@dataclass(slots=True)
class _ConstraintSpec:
    code: str
    recommended_severity: str
    expression_raw: str
    program: ExpressionProgram


class _ReferencedVariableVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.referenced_variables: set[str] = set()

    def visit_Name(self, node: ast.Name) -> Any:
        self.referenced_variables.add(node.id)


def extract_expression_variables(expression: str) -> set[str]:
    tree = ast.parse(expression, mode="eval")
    visitor = _ReferencedVariableVisitor()
    visitor.visit(tree)
    return visitor.referenced_variables


@dataclass(slots=True)
class _DynamicRuleSpec:
    condition: ExpressionProgram | None
    formula: ExpressionProgram | None
    value: Any = None


@dataclass(slots=True)
class _DefaultSpec:
    name: str
    mode: str
    value: Any = None
    rules: list[_DynamicRuleSpec] | None = None


@dataclass(slots=True)
class RuleEngine:
    ruleset: dict[str, Any]
    functions: dict[str, Callable[..., Any]]
    defaults: list[_DefaultSpec]
    constraints: list[_ConstraintSpec]
    calculations: list[_CalculationSpec]

    @classmethod
    def from_ruleset(
        cls,
        ruleset: dict[str, Any],
        extra_functions: dict[str, Callable[..., Any]] | None = None,
    ) -> RuleEngine:
        normalized = normalize_ruleset(ruleset)
        functions = _resolve_eval_functions(extra_functions)
        _attach_ruleset_custom_functions(normalized, functions)

        defaults = [_compile_default_spec(entry, functions) for entry in normalized.get("default_values", [])]
        constraints = [
            _ConstraintSpec(
                code=str(
                    constraint.get("reason_code")
                    or constraint.get("message")
                    or DEFAULT_CONSTRAINT_REASON_CODE
                ),
                recommended_severity=str(constraint.get("recommended_severity", "BLOCK")),
                expression_raw=str(constraint["expression"]),
                program=compile_expression(str(constraint["expression"]), functions),
            )
            for constraint in normalized.get("constraints", [])
        ]
        calculations = [
            _CalculationSpec(
                name=str(calc["name"]),
                program=compile_expression(str(calc["formula"]), functions),
            )
            for calc in normalized.get("calculations", [])
        ]

        return cls(
            ruleset=normalized,
            functions=functions,
            defaults=defaults,
            constraints=constraints,
            calculations=calculations,
        )

    def evaluate(self, configuration: dict[str, Any]) -> EvaluationResult:
        resolved_configuration = self.apply_default_values(configuration)

        violations: list[Violation] = []
        for constraint in self.constraints:
            result = evaluate_program(constraint.program, resolved_configuration, self.functions)
            if not bool(result):
                referenced_variables = sorted(extract_expression_variables(constraint.expression_raw))
                snapshot = {
                    variable: resolved_configuration.get(variable)
                    for variable in referenced_variables
                    if variable in resolved_configuration
                }
                violation = Violation(
                    code=constraint.code,
                    recommended_severity=constraint.recommended_severity,
                    meta={
                        "expression_raw": constraint.expression_raw,
                        "referenced_variables": referenced_variables,
                        "snapshot": snapshot,
                        "evaluated_to": False,
                    },
                    rule={"type": "CONSTRAINT", "raw": constraint.expression_raw},
                )
                violations.append(violation)
                logger.info(
                    "constraint_violation",
                    extra={
                        "code": violation.code,
                        "recommended_severity": violation.recommended_severity,
                        "meta": violation.meta,
                    },
                )

        calculations: dict[str, float] = {}
        working_context = {**resolved_configuration}
        for calc in self.calculations:
            value = evaluate_program(calc.program, working_context, self.functions)
            calculations[calc.name] = float(value)
            working_context[calc.name] = value

        return EvaluationResult(
            valid=(len(violations) == 0),
            calculations=calculations,
            violations=violations,
            resolved_configuration=resolved_configuration,
        )

    def apply_default_values(self, configuration: dict[str, Any]) -> dict[str, Any]:
        resolved = {**configuration}
        for default in self.defaults:
            if default.name in resolved:
                continue
            resolved[default.name] = _resolve_compiled_default(default, resolved, self.functions)
        return resolved

    def optimize(self, domains: dict[str, list[Any]], objective: str, maximize: bool = False) -> dict[str, Any]:
        keys = list(domains.keys())
        objective_program = compile_expression(objective, self.functions)

        best_score = float("-inf") if maximize else float("inf")
        best_config: dict[str, Any] | None = None

        for values in itertools.product(*(domains[key] for key in keys)):
            candidate = dict(zip(keys, values, strict=True))
            evaluated = self.evaluate(candidate)
            if not evaluated.valid:
                continue
            score = float(
                evaluate_program(
                    objective_program,
                    {**evaluated.resolved_configuration, **evaluated.calculations},
                    self.functions,
                )
            )
            is_better = score > best_score if maximize else score < best_score
            if is_better:
                best_score = score
                best_config = {
                    **evaluated.resolved_configuration,
                    **evaluated.calculations,
                    "objective_score": score,
                }

        if best_config is None:
            raise ValueError("No valid configuration found for provided domains/rules")

        return best_config


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
        "memo_parameters": list(base.get("memo_parameters", [])),
        **{
            key: value
            for key, value in base.items()
            if key
            not in {
                "default_values",
                "constraints",
                "calculations",
                "schema_version",
                "custom_functions",
                "memo_parameters",
            }
        },
    }


def expression_references(expression: str) -> set[str]:
    return extract_expression_variables(expression)


def infer_memo_parameters(ruleset: dict[str, Any] | None) -> list[dict[str, Any]]:
    normalized = normalize_ruleset(ruleset)
    parameters: dict[str, dict[str, Any]] = {}

    for raw_param in normalized.get("memo_parameters", []):
        name = str(raw_param.get("name", "")).strip()
        if not name:
            continue
        param = {
            "name": name,
            "label": raw_param.get("label", name.replace("_", " ").title()),
            "data_type": raw_param.get("data_type", "string"),
            "parameter_class": raw_param.get("parameter_class", "required_input"),
            "rules_engine_property": raw_param.get("rules_engine_property", name),
            "inferred": bool(raw_param.get("inferred", False)),
        }
        parameters[name] = param

    output_names = {str(item.get("name")) for item in normalized.get("default_values", [])}
    output_names.update(str(item.get("name")) for item in normalized.get("calculations", []))

    names_referenced: set[str] = set()
    for constraint in normalized.get("constraints", []):
        names_referenced.update(expression_references(str(constraint["expression"])))
    for calc in normalized.get("calculations", []):
        names_referenced.update(expression_references(str(calc["formula"])))
    for default in normalized.get("default_values", []):
        for rule in default.get("rules", []):
            if rule.get("condition"):
                names_referenced.update(expression_references(str(rule["condition"])))
            if rule.get("formula"):
                names_referenced.update(expression_references(str(rule["formula"])))

    for custom in normalized.get("custom_functions", []):
        args = {str(arg) for arg in custom.get("args", [])}
        refs = expression_references(str(custom.get("expression", ""))) - args
        names_referenced.update(refs)

    allowed_function_names = set(ALLOWED_FUNCTIONS) | set(CUSTOM_FUNCTIONS)
    allowed_function_names.update(str(item.get("name")) for item in normalized.get("custom_functions", []))
    candidate_inputs = names_referenced - output_names - allowed_function_names

    for name in sorted(candidate_inputs):
        if name in parameters:
            continue
        parameters[name] = {
            "name": name,
            "label": name.replace("_", " ").title(),
            "data_type": "number",
            "parameter_class": "required_input",
            "rules_engine_property": name,
            "inferred": True,
        }

    for default_name in sorted(str(item.get("name")) for item in normalized.get("default_values", [])):
        if default_name in parameters:
            continue
        parameters[default_name] = {
            "name": default_name,
            "label": default_name.replace("_", " ").title(),
            "data_type": "number",
            "parameter_class": "optional_input",
            "rules_engine_property": default_name,
            "inferred": True,
        }

    for calc_name in sorted(str(item.get("name")) for item in normalized.get("calculations", [])):
        if calc_name in parameters:
            continue
        parameters[calc_name] = {
            "name": calc_name,
            "label": calc_name.replace("_", " ").title(),
            "data_type": "number",
            "parameter_class": "intermediate",
            "rules_engine_property": calc_name,
            "inferred": True,
        }

    return sorted(parameters.values(), key=lambda item: item["name"])


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


def compile_expression(
    expression: str,
    functions: dict[str, Callable[..., Any]] | None = None,
    extra_functions: dict[str, Callable[..., Any]] | None = None,
) -> ExpressionProgram:
    resolved_functions = functions if functions is not None else _resolve_eval_functions(extra_functions)
    tree = ast.parse(expression, mode="eval")
    _validate_ast(tree, set(resolved_functions))
    return ExpressionProgram(source=expression, code=compile(tree, "<rules>", "eval"))


def evaluate_program(
    program: ExpressionProgram,
    context: dict[str, Any],
    functions: dict[str, Callable[..., Any]] | None = None,
    extra_functions: dict[str, Callable[..., Any]] | None = None,
) -> Any:
    resolved_functions = functions if functions is not None else _resolve_eval_functions(extra_functions)
    return eval(program.code, {"__builtins__": {}, **resolved_functions}, context)


def safe_eval(
    expression: str,
    context: dict[str, Any],
    extra_functions: dict[str, Callable[..., Any]] | None = None,
) -> Any:
    functions = _resolve_eval_functions(extra_functions)
    program = compile_expression(expression, functions=functions)
    return evaluate_program(program, context, functions=functions)


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
                expression, reason_code = body.split("::", 1)
                reason_code = reason_code.strip()
            else:
                expression = body
                reason_code = DEFAULT_CONSTRAINT_REASON_CODE
            ruleset["constraints"].append({"expression": expression.strip(), "reason_code": reason_code})
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
        reason_code = constraint.get("reason_code") or constraint.get("message") or DEFAULT_CONSTRAINT_REASON_CODE
        lines.append(f"CONSTRAINT {constraint['expression']} :: {reason_code}")

    for calc in normalized["calculations"]:
        lines.append(f"CALC {calc['name']} = {calc['formula']}")

    for func in normalized.get("custom_functions", []):
        args = ", ".join(func.get("args", []))
        lines.append(f"FUNCTION {func['name']}({args}) = {func['expression']}")

    return "\n".join(lines)


def _compile_default_spec(
    default_entry: dict[str, Any],
    functions: dict[str, Callable[..., Any]],
) -> _DefaultSpec:
    mode = default_entry.get("mode", "static")
    if mode == "static":
        if "value" not in default_entry:
            raise ValueError("static defaults must define a value")
        return _DefaultSpec(name=str(default_entry["name"]), mode=mode, value=default_entry["value"])

    if mode != "dynamic":
        raise ValueError(f"unsupported default mode: {mode}")

    rules: list[_DynamicRuleSpec] = []
    for rule in default_entry.get("rules", []):
        condition_program = None
        formula_program = None
        if "condition" in rule and rule["condition"] is not None:
            condition_program = compile_expression(str(rule["condition"]), functions=functions)
        if "formula" in rule:
            formula_program = compile_expression(str(rule["formula"]), functions=functions)
        if formula_program is None and "value" not in rule:
            raise ValueError("dynamic default rule must define value or formula")
        rules.append(_DynamicRuleSpec(condition=condition_program, formula=formula_program, value=rule.get("value")))

    return _DefaultSpec(name=str(default_entry["name"]), mode=mode, rules=rules)


def _resolve_compiled_default(
    default_spec: _DefaultSpec,
    context: dict[str, Any],
    functions: dict[str, Callable[..., Any]],
) -> Any:
    if default_spec.mode == "static":
        return default_spec.value

    for rule in default_spec.rules or []:
        if rule.condition is not None and not bool(evaluate_program(rule.condition, context, functions)):
            continue
        if rule.formula is not None:
            return evaluate_program(rule.formula, context, functions)
        return rule.value

    raise ValueError(f"no dynamic default matched for field: {default_spec.name}")


def _attach_ruleset_custom_functions(
    ruleset: dict[str, Any],
    functions: dict[str, Callable[..., Any]],
) -> None:
    for custom in ruleset.get("custom_functions", []):
        name = str(custom["name"])
        args = [str(arg) for arg in custom.get("args", [])]
        program = compile_expression(str(custom["expression"]), functions=functions)

        def _custom_callable(*values: Any, _args: list[str] = args, _program: ExpressionProgram = program) -> Any:
            if len(values) != len(_args):
                raise ValueError(f"function expected {len(_args)} args, got {len(values)}")
            context = dict(zip(_args, values, strict=True))
            return evaluate_program(_program, context, functions)

        functions[name] = _custom_callable


def apply_default_values(ruleset: dict[str, Any], configuration: dict[str, Any]) -> dict[str, Any]:
    engine = RuleEngine.from_ruleset(ruleset)
    return engine.apply_default_values(configuration)


def evaluate_rules(ruleset: dict[str, Any], configuration: dict[str, Any]) -> EvaluationResult:
    engine = RuleEngine.from_ruleset(ruleset)
    return engine.evaluate(configuration)


def optimize_configuration(
    domains: dict[str, list[Any]],
    objective: str,
    ruleset: dict[str, Any],
    maximize: bool = False,
) -> dict[str, Any]:
    engine = RuleEngine.from_ruleset(ruleset)
    return engine.optimize(domains=domains, objective=objective, maximize=maximize)
