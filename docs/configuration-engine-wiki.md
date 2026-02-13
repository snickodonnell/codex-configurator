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

Example (default fallback ruleset):

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


### Default input values (static and dynamic)

Rulesets can optionally define `default_values` to fill missing configuration inputs before constraints and calculations run.

- `mode: "static"`: assigns a fixed `value`.
- `mode: "dynamic"`: evaluates `rules` in order and uses the first matching rule. A rule can define:
  - `condition`: expression that must evaluate truthy (optional for final fallback)
  - `value`: fixed value
  - `formula`: computed value expression

Example:

```json
{
  "default_values": [
    {"name": "discount", "mode": "static", "value": 0.05},
    {
      "name": "region",
      "mode": "dynamic",
      "rules": [
        {"condition": "country == 'DE'", "value": "EU"},
        {"value": "NA"}
      ]
    }
  ]
}
```

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

This section is a practical path you can follow for a new product rollout.

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
- **Payload**: JSON object with `constraints` and `calculations`.

Recommended practice:

- Keep constraint messages customer-friendly.
- Keep formulas purely numeric and deterministic.
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

For new customers, insert a row in `customer_access` with a JSON array of allowed environments.

### Step 5: Evaluate a draft configuration

Use the configurator API:

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

If `valid` is false, return violations to the UI and prevent final submit until corrected.

### Step 6: Submit finalized specification

After a configuration is valid and accepted by the user/business flow:

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

Successful response:

```json
{"status":"submitted"}
```

### Step 7: (Optional) Optimize a product automatically

For guided selling or price optimization, call the Rules Engine `/optimize` endpoint with finite domains:

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

The engine brute-forces candidate combinations, filters invalid configurations, computes objective score, and returns the best valid candidate.

## 4. Rules expression language and safety

Expressions are parsed with Python AST and validated against an allowlist.

### Allowed operations

- Arithmetic: `+ - * / % **`
- Comparisons: `== != > >= < <=`
- Boolean logic: `and`, `or`, `not`
- Unary: `+x`, `-x`
- Constants and variable names from context
- Allowed functions: `abs`, `ceil`, `floor`, `max`, `min`, `round`, `sqrt`

### What this means for rule authors

- No attribute access, imports, comprehensions, lambdas, or arbitrary function calls.
- Keep formulas simple and explicit.
- Treat missing fields as authoring errors and ensure required inputs are supplied by the caller.

## 5. Data model reference

- `rulesets`: authored rule payloads by name/environment.
- `deployments`: active ruleset pointer for each environment.
- `customer_access`: API key and environment allowlist by customer.
- `configuration_states`: snapshots of evaluated draft configurations.
- `specifications`: final submitted specs.
- `frontend_enhancements`: admin backlog/visibility items used by the landing app.

## 6. Recommended product-delivery workflow

1. Model business rules with a product manager + pricing + engineering.
2. Author ruleset in `dev`.
3. Create automated tests for edge constraints and calculations.
4. Deploy to `dev` and run API-level checks.
5. Validate configurator UX messages against `violations` output.
6. Promote ruleset to `prod`.
7. Monitor submitted specs and iterate with versioned rulesets.

## 7. Quality checklist for next steps

Use this as a review template before rollout:

- [ ] Ruleset has explicit constraint messages.
- [ ] Calculations are ordered and reference-safe.
- [ ] `dev` deployment tested with at least one valid and one invalid configuration.
- [ ] Customer access rows exist for each pilot customer.
- [ ] Submit payload includes required downstream fields.
- [ ] Optimization objective matches business KPI (margin, total, score, etc.).
- [ ] Rollback plan exists (re-deploy previous ruleset id).

## 8. Future expansion ideas

- Versioned approval flow for rules (draft → approved → deployed).
- Change audit logs for author/deployer identity.
- OpenAPI contracts for all JSON endpoints.
- Better auth (OIDC/SAML) and scoped API tokens.
- Asynchronous optimization jobs for large domains.
