# Demo deployment checklist

Use this checklist to validate the four-app workflow before a customer demo.

## 1) Environment setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## 2) Automated confidence checks

```bash
pytest -q
pytest -q tests/test_demo_readiness.py
```

## 3) Run all apps

```bash
python -m sales_configurator landing --port 8000 --db ./data.db
python -m sales_configurator rules --port 8001 --db ./data.db
python -m sales_configurator configurator --port 8002 --db ./data.db
python -m sales_configurator experience --port 8003 --db ./data.db
```

## 4) Readiness probes

Each app now exposes `GET /healthz` for load balancer and deploy smoke checks.

```bash
curl -s http://localhost:8000/healthz
curl -s http://localhost:8001/healthz
curl -s http://localhost:8002/healthz
curl -s http://localhost:8003/healthz
```

Expected response shape:

```json
{"status":"ok","app":"landing"}
```

(`app` varies by service.)

## 5) Demo user journey

1. In **RuleCanvas**, create rules via JSON or pseudocode.
2. Send the ruleset to Studio, map required controls in **Experience Studio**.
3. Request approval, approve, and deploy in RuleCanvas.
4. In **ShopFloor Configurator**, evaluate a customer configuration and validate totals/violations.

The same flow is covered automatically in `test_demo_journey_rules_to_studio_to_customer_runtime`.
