# Configuration Engine Wiki

This wiki explains how to build and operate a product configuration workflow in this repository end to end: authoring rules, deploying to environments, evaluating customer configurations, and submitting final specifications.

## 1. System overview

The MVP is split into three Flask applications that share a SQLite database:

- **Admin Landing App** (`landing`) for visibility and launch links.
- **Rules Engine App** (`rules`) for authoring and deploying rulesets.
- **Configurator App** (`configurator`) for evaluating and submitting customer configurations.

All services initialize the same schema and can point to the same DB file with `--db` / `RULES_DB_PATH`.

## 2. Core concepts

### Ruleset
A ruleset is JSON with:

- `constraints`: boolean expressions that must evaluate truthy.
- `calculations`: formulas evaluated sequentially to derive numeric outputs.
- `default_values`: optional static/dynamic defaults applied to missing fields.
- `custom_functions`: optional expression-defined functions usable inside formulas.

Example:

```json
{
  "constraints": [
    {"expression": "quantity >= 1", "message": "Quantity must be at least 1."},
    {
      "expression": "(region != 'EU') or (discount <= 0.2)",
      "message": "EU discount cannot exceed 20%."
    }
  ],
  "calculations": [
    {"name": "unit_price", "formula": "base_price * (1 - discount)"},
    {"name": "total_price", "formula": "unit_price * quantity"}
  ]
}
```

### Rule engine phases

The runtime has clear phases to support extension:

1. **Normalization** – ensure stable schema keys.
2. **Compilation** – parse and validate expressions into reusable programs.
3. **Evaluation** – apply defaults, constraints, then calculations.
4. **Optimization** – score valid candidate configurations against objective.

Because these concerns are separated, future work (rule package imports, simulation, static analysis, authoring assistance) can be added with less risk.

### Default input values (static and dynamic)

Rulesets can define `default_values` to fill missing configuration inputs before constraints and calculations run.

- `mode: "static"`: assigns a fixed `value`.
- `mode: "dynamic"`: evaluates `rules` in order and uses the first matching rule. A rule can define:
  - `condition`: expression that must evaluate truthy (optional for final fallback)
  - `value`: fixed value
  - `formula`: computed value expression

When a caller explicitly provides a field, that value is preserved and defaults are not applied for that field.

### Deployment
A deployment maps one environment (`dev`, `prod`, etc.) to one active ruleset. A new deployment to the same environment upserts and replaces the previous mapping.

### Configuration lifecycle
1. Customer submits a configuration to `/api/evaluate`.
2. App authorizes the customer/environment via `customer_access`.
3. Active rules are evaluated.
4. Configuration snapshot is stored in `configuration_states`.
5. Later, finalized payload is sent to `/api/submit` and stored in `specifications`.

## 3. Build a product in detail (walkthrough)

### Step 0: Start services

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m sales_configurator landing --port 8000 --db ./data.db
python -m sales_configurator rules --port 8001 --db ./data.db
python -m sales_configurator configurator --port 8002 --db ./data.db
```

Admin login for all apps:

- username: `admin`
- password: `admin`

### Step 1: Define product variables and business rules

Before touching the app, define:

- Input attributes (for example `quantity`, `region`, `discount`, `base_price`).
- Validation policy (must-have constraints).
- Derived outputs required by pricing/quote (for example `unit_price`, `total_price`, taxes, margin).

Write constraints and formulas in a deterministic order. Calculations can reference prior calculations because formulas are evaluated sequentially with a working context.

### Step 2: Author a ruleset in the Rules Engine app

Open `http://localhost:8001`, log in, and create a ruleset:

- **Name**: semantic versioning style is recommended, e.g. `widget-pricing-v1.0.0`.
- **Environment field**: authoring target (often `dev`).
- **DSL or payload**: use DSL for readability, JSON for advanced cases.

Recommended practice:

- Keep constraint messages customer-friendly.
- Keep formulas numeric and deterministic.
- Add one rule change at a time so test failures are isolated.

### Step 3: Deploy the ruleset to an environment

From the rules table in the Rules Engine app, deploy your chosen ruleset to an environment:

- Deploy to `dev` first.
- Run evaluation tests.
- Promote same or newer ruleset to `prod` when validated.

Because deployment is an upsert by environment, each environment has exactly one active ruleset pointer.

### Step 4: Verify customer access policy

Evaluation and submit endpoints require:

- `customer_id`
- `api_key`
- target `environment`

Default seeded test user:

- `customer_id`: `demo-customer`
- `api_key`: `demo-key`
- allowed environments: `dev`, `prod`

### Step 5: Evaluate a draft configuration

```bash
curl -X POST http://localhost:8002/api/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "customer_id": "demo-customer",
    "api_key": "demo-key",
    "environment": "dev",
    "configuration": {
      "quantity": 2,
      "base_price": 100,
      "discount": 0.1,
      "region": "NA"
    }
  }'
```

Expected response shape:

```json
{
  "valid": true,
  "calculations": {"unit_price": 90.0, "total_price": 180.0},
  "violations": []
}
```

### Step 6: Submit finalized specification

```bash
curl -X POST http://localhost:8002/api/submit \
  -H 'content-type: application/json' \
  -d '{
    "customer_id": "demo-customer",
    "api_key": "demo-key",
    "environment": "dev",
    "specification": {
      "product": "Widget Pro",
      "configuration": {
        "quantity": 2,
        "base_price": 100,
        "discount": 0.1,
        "region": "NA"
      },
      "calculated_total": 180.0
    }
  }'
```

### Step 7: (Optional) Optimize a product automatically

```bash
curl -X POST http://localhost:8001/optimize \
  -H 'content-type: application/json' \
  -d '{
    "environment": "dev",
    "domains": {
      "quantity": [1,2,3],
      "discount": [0,0.1,0.2],
      "base_price": [100],
      "region": ["NA", "EU"]
    },
    "objective": "total_price",
    "maximize": false
  }'
```

## 4. Rules expression language and safety

Expressions are parsed with Python AST and validated against an allowlist.

### Allowed operations

- Arithmetic: `+ - * / % **`
- Comparisons: `== != > >= < <=`
- Boolean logic: `and`, `or`, `not`
- Unary: `+x`, `-x`
- Constants and variable names from context
- Allowed functions: `abs`, `ceil`, `floor`, `max`, `min`, `round`, `sqrt`
- Custom ruleset functions defined with `FUNCTION name(args...) = expression`

No attribute access, imports, comprehensions, lambdas, or arbitrary function calls are permitted.

## 5. Data model reference

- `rulesets`: authored rule payloads by name/environment.
- `deployments`: active ruleset pointer for each environment.
- `customer_access`: API key and environment allowlist by customer.
- `configuration_states`: snapshots of evaluated draft configurations.
- `specifications`: final submitted specs.
- `frontend_enhancements`: admin backlog/visibility items used by the landing app.

## 6. Recommended product-delivery workflow

1. Model business rules with product + pricing + engineering.
2. Author ruleset in `dev`.
3. Create automated tests for edge constraints, defaults, and calculations.
4. Deploy to `dev` and run API-level checks.
5. Validate configurator UX messages against `violations` output.
6. Promote ruleset to `prod`.
7. Monitor submitted specs and iterate with versioned rulesets.

## 7. UI development and extensibility notes

The Rules Engine HTML now includes named UI regions (`data-ui-region`) and card-based sections so future front-end work can be layered incrementally:

- Replace DSL textarea with a visual rule builder.
- Add inline syntax/semantic validation hints.
- Add per-ruleset test fixture runners.
- Add side-by-side diffing between versions.

This allows progressive enhancement without rewriting route contracts.

## 8. Test strategy

The repository now emphasizes logical coverage across engine and integration behavior.

- **Engine tests** cover unsafe AST rejection, function handling, parser failure modes, dynamic defaults, optimization failure/success paths, and reusable compiled engines.
- **App tests** cover auth boundaries, login/logout behavior, rule authoring errors, deployment/evaluation APIs, and persistence side effects.

Run:

```bash
pytest
```

## 9. Future expansion ideas

- Versioned approval flow for rules (draft → approved → deployed).
- Change audit logs for author/deployer identity.
- OpenAPI contracts for all JSON endpoints.
- Better auth (OIDC/SAML) and scoped API tokens.
- Asynchronous optimization jobs for large domains.
