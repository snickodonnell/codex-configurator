# Sales Configurator MVP

This repository provides a role-segmented configuration platform with four Flask apps:

1. **Launchpad Orbit (`landing`)** – admin launch + visibility.
2. **RuleCanvas (`rules`)** – rules authoring and release workflow control.
3. **Experience Studio (`experience`)** – UX mapping editor with governance enforcement.
4. **ShopFloor Configurator (`configurator`)** – customer-facing runtime UI.

## New workflow lifecycle

Rule delivery now follows a governed pipeline:

`RuleCanvas Draft → Send to Studio → UX Mapping Update → Request Approval → Approve → Deploy`

### Release workflow skeleton

Each ruleset now has a workflow record (`release_workflows`) with:

- state (`draft`, `in_studio`, `pending_approval`, `approved`, `deployed`, `rolled_back`)
- UX sync requirement (`requires_ux_update`)
- UX schema version tracking (`ux_schema_version`)
- approval metadata (`approved_by`)

Deployments are blocked unless:

- the ruleset is approved
- Studio mapping has been updated when required

## Governance and mandatory UX update

Rule changes generate a rules fingerprint from inferred parameters (`name`, `data_type`, class, and allowed controls). If fingerprint changes, the new release is flagged `requires_ux_update=1`.

Studio enforces governance from `ruleset_parameter_profiles`:

- **boolean**: `radio_boolean`, `dropdown`, `button_group`
- **number**: `number`, `slider`, `dropdown`, `button_group`
- **string**: `text`, `dropdown`, `button_group`
- **intermediate**: `text`

Disallowed control types are rejected by API.

## Versioning, history, rollback

- UI mapping updates increment `schema_version` and write to `ui_schema_history`.
- Deployment events append to `deployment_history`.
- `/rollback` restores the previous deployed ruleset for an environment.

## Runtime consumption

ShopFloor consumes the active deployed ruleset + matching studio mappings via:

- `GET /api/ui-schema?environment=dev`

Core rules logic remains unchanged and still executes through `evaluate_rules`.


## RuleCanvas DSL quick reference

Constraint suffixes are reason codes (not human-readable messages):

```text
DEFAULT discount = 0.05
DEFAULT tier WHEN quantity >= 10 = "bulk"
CALC total_price = base_price * quantity * (1 - discount)
FUNCTION margin(price, cost) = price - cost
CONSTRAINT quantity >= 1 :: ERR_QUANTITY_REQUIRED
CONSTRAINT discount <= 0.2
```

If a `CONSTRAINT` omits `:: CODE`, the engine applies `ERR_CONSTRAINT_FAILED`.

## Violation response shape

`violations` is a list of objects (not `list[str]`). Each item includes `code`, `recommended_severity`, and `rule`.
For convenience, `violation_codes` is also returned as a list of strings.

## Runtime safety and observability

- API routes now use a shared error policy:
  - malformed JSON requests return `400 {"error": "invalid request payload"}`
  - HTTP errors from `abort(...)` are returned as standardized JSON for API clients
  - unhandled exceptions are logged server-side and returned as `500 {"error": "internal server error"}` for API routes
- Authentication, rules workflow transitions, deploy/rollback events, and Studio mapping updates are logged.
- Configuration state persistence now emits `configuration_state_changed` logs so operators can trace customer/runtime state transitions.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m sales_configurator landing --port 8000 --db ./data.db
python -m sales_configurator rules --port 8001 --db ./data.db
python -m sales_configurator configurator --port 8002 --db ./data.db
python -m sales_configurator experience --port 8003 --db ./data.db
```

## Auth

- Admin (full): `admin/admin`
- Studio editor: `ux-admin/ux-admin`

## Demo readiness quickstart

Run the full automated suite (including end-to-end demo journey coverage):

```bash
pytest -q
pytest -q tests/test_demo_readiness.py
```

Health checks for deployment probes:

```bash
curl -s http://localhost:8000/healthz
curl -s http://localhost:8001/healthz
curl -s http://localhost:8002/healthz
curl -s http://localhost:8003/healthz
```

For a full pre-demo checklist, see [Demo Deployment Checklist](docs/demo-deployment-checklist.md).

## Docs

- [Configuration Engine Wiki](docs/configuration-engine-wiki.md)
- [Experience Studio Wiki](docs/experience-studio-wiki.md)

## Tests

```bash
pytest
```
