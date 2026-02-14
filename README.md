# Sales Configurator MVP

This repository contains an MVP sales-configuration platform with **three independent web applications**:

1. **Admin Landing App** – launch page for core functions and admin visibility across rules, front-end enhancements, and end-user configurations.
2. **Rules Engine App** – manages rule authoring and environment deployment.
3. **Configurator Front-End App** – customer-facing configuration workflow that consumes deployed rules.

The implementation favors minimal dependencies, deterministic rules processing, and architecture that can grow into more advanced rule authoring and UI workflows.

## Why this stack

- **Python + Flask** for fast MVP delivery and low operational complexity.
- **SQLite** for local persistence and reproducible development/test setup.
- **Safe AST-based rule evaluation** for boolean logic and dynamic calculations.
- **Compiled rule engine core** that separates parsing, compilation, and runtime evaluation.
- **Discrete optimization routine** (combinatorial search) to support advanced mathematical optimization in rules workflows.

## Features implemented

- Admin landing page with launch links and portfolio visibility for rulesets, front-end enhancements, and end-user configuration activity.
- Ruleset CRUD-lite (create + list + edit).
- Visual rules workspace with product switching, category/sub-category organization, and sortable execution order.
- Rule cards default to read-only and can be toggled editable on click for safer authoring.
- Environment deployments (`dev`, `prod`, etc.) with active ruleset mapping.
- Customer access control per environment via API key.
- Config evaluation endpoint:
  - applies static and dynamic default values
  - validates constraints (boolean logic)
  - computes formulas (dynamic calculations)
- Configuration state persistence.
- Final submission persistence as specifications.
- Optimization endpoint (`/optimize`) to find best valid configuration from domains/objective.
- Expanded test suite covering safety checks, parser errors, custom functions, constraint violations, optimization edge cases, app auth flows, and persistence behavior.

## Project layout

```
src/sales_configurator/
  app.py                 # Flask app factories and routes
  db.py                  # schema + db helpers
  rules_engine.py        # rule compilation, safe evaluator, optimization engine
  __main__.py            # CLI launcher for each service
  templates/
    landing/index.html
    rules_engine/index.html
    configurator/index.html
docs/
  configuration-engine-wiki.md
tests/
  test_rules_engine.py
  test_apps.py
```

## Engine architecture

The rules engine now uses a reusable `RuleEngine` abstraction:

1. **Normalize** the incoming ruleset shape.
2. **Compile** constraints, calculations, defaults, and objective expressions into validated AST programs.
3. **Evaluate** with a runtime context while preserving safety restrictions.
4. **Optimize** by evaluating only valid candidates and scoring objective programs against resolved configuration + calculated fields.

This structure makes it easier to add advanced capabilities (rule libraries, scenario simulation, partial evaluation, caching strategies) without tightly coupling logic to Flask route handlers.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Run admin landing app

```bash
python -m sales_configurator landing --port 8000 --db ./data.db
```

Open: `http://localhost:8000`

### Run rules engine app

```bash
python -m sales_configurator rules --port 8001 --db ./data.db
```

Open: `http://localhost:8001`

### Run configurator app

```bash
python -m sales_configurator configurator --port 8002 --db ./data.db
```

Open: `http://localhost:8002`

Demo credentials in configurator UI:
- customer id: `demo-customer`
- api key: `demo-key`

## Authentication

Both web apps require a session-based admin login before access.

- username: `admin`
- password: `admin`

Use `/login` on each app URL and `/logout` to end the session.

## API examples

Evaluate configuration:

```bash
curl -X POST http://localhost:8002/api/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "customer_id": "demo-customer",
    "api_key": "demo-key",
    "environment": "dev",
    "configuration": {"quantity": 2, "base_price": 100, "discount": 0.1, "region": "NA"}
  }'
```


Rules workspace snapshot:

```bash
curl -s http://localhost:8001/api/workspace
```

Create a product in workspace:

```bash
curl -X POST http://localhost:8001/api/workspace/products \
  -H 'content-type: application/json' \
  -d '{"name": "Servers", "description": "Rack and blade portfolio"}'
```

Optimize in rules engine:

```bash
curl -X POST http://localhost:8001/optimize \
  -H 'content-type: application/json' \
  -d '{
    "environment": "dev",
    "domains": {"quantity": [1,2,3], "discount": [0,0.1,0.2], "base_price": [100]},
    "objective": "total_price",
    "maximize": false
  }'
```

## Wiki

- [Configuration Engine Wiki](docs/configuration-engine-wiki.md)

## Tests

```bash
pytest
```

## Suggested next steps

- Introduce auth provider integration (OIDC/SAML).
- Move deployment/versioning into explicit workflow states.
- Add async task queue for large optimization jobs.
- Add migration tooling (Alembic) when moving off MVP.
- Introduce typed API contracts (OpenAPI-first, generated clients).
