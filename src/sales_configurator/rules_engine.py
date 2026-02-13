from __future__ import annotations

import ast
import itertools
import math
from dataclasses import dataclass
from typing import Any

ALLOWED_FUNCTIONS = {
    "abs": abs,
    "ceil": math.ceil,
    "floor": math.floor,
    "max": max,
    "min": min,
    "round": round,
    "sqrt": math.sqrt,
}

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



def _validate_ast(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise UnsafeExpressionError(f"Unsupported expression node: {type(node).__name__}")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in ALLOWED_FUNCTIONS:
                raise UnsafeExpressionError("Unsupported function call")


def safe_eval(expression: str, context: dict[str, Any]) -> Any:
    tree = ast.parse(expression, mode="eval")
    _validate_ast(tree)
    compiled = compile(tree, "<rules>", "eval")
    return eval(compiled, {"__builtins__": {}, **ALLOWED_FUNCTIONS}, context)


@dataclass(slots=True)
class EvaluationResult:
    valid: bool
    calculations: dict[str, float]
    violations: list[str]



def evaluate_rules(ruleset: dict[str, Any], configuration: dict[str, Any]) -> EvaluationResult:
    violations: list[str] = []
    for constraint in ruleset.get("constraints", []):
        result = safe_eval(constraint["expression"], configuration)
        if not bool(result):
            violations.append(constraint["message"])

    calculations: dict[str, float] = {}
    working_context = {**configuration}
    for calc in ruleset.get("calculations", []):
        value = safe_eval(calc["formula"], working_context)
        calculations[calc["name"]] = float(value)
        working_context[calc["name"]] = value

    return EvaluationResult(valid=(len(violations) == 0), calculations=calculations, violations=violations)



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
