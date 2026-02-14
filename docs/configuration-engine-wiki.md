# Configuration Engine Wiki

This wiki describes the governed configuration lifecycle across RuleCanvas, Experience Studio, and ShopFloor.

## Apps and responsibilities

- **Launchpad Orbit** (`landing`): launch/navigation and platform visibility.
- **RuleCanvas** (`rules`): rules authoring, release workflow transitions, and deployment.
- **Experience Studio** (`experience`): UI mapping editor with governance enforcement.
- **ShopFloor** (`configurator`): end-user configuration runtime.

## Release workflow (skeleton)

1. **Draft**: ruleset is created/updated.
2. **In Studio**: ruleset is sent to UX mapping stage.
3. **Pending Approval**: Studio updates complete, awaiting approval.
4. **Approved**: release is approved by admin role.
5. **Deployed**: active in an environment.
6. **Rolled Back**: prior deployment restored.

Workflow state is stored in `release_workflows`.

## Governance + UX update requirements

Rulesets now produce parameter profiles (`ruleset_parameter_profiles`) from inferred memo parameters.

These profiles define allowed UI controls:

- boolean: `radio_boolean`, `dropdown`, `button_group`
- number: `number`, `slider`, `dropdown`, `button_group`
- string: `text`, `dropdown`, `button_group`
- intermediate: `text`

Experience Studio validates selected control types against this governance.

A rules fingerprint is tracked per ruleset lineage. If changed from a prior release, `requires_ux_update=1` is set. Until Studio updates are saved, approval and deployment are blocked.

## Versioning/history/rollback

- `ui_schema_history` stores Studio schema versions.
- `deployment_history` tracks deploy/replaced/rollback events.
- `/rollback` restores prior deployment in the same environment.

## Runtime contract

ShopFloor consumes `GET /api/ui-schema?environment=...`, which merges deployed ruleset parameters with mappings scoped to deployed `ruleset_id`.

Core rules logic remains in `evaluate_rules`; Studio does not alter rule execution.

## Test coverage focus

- role access boundaries
- workflow deployment gating
- governance validation failures
- Studio mapping persistence into ShopFloor schema
- rollback behavior


## Rule DSL notes

Use reason codes for constraints in RuleCanvas DSL:

```text
CONSTRAINT quantity >= 1 :: ERR_QUANTITY_REQUIRED
```

Do not use human-readable messages after `::`. If omitted, the engine defaults to `ERR_CONSTRAINT_FAILED`.

Runtime API returns `violations` as objects (`code`, `recommended_severity`, `rule`) plus `violation_codes` as string codes for convenience.
