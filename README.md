# Sales Configurator MVP

This repository now ships a **role-segmented configuration platform** with four independent Flask applications:

1. **Launchpad Orbit (`landing`)** – admin launch page with links and operational visibility.
2. **RuleCanvas (`rules`)** – rules authoring + deployment workspace.
3. **Experience Studio (`experience`)** – front-end mapping editor for UI control composition.
4. **ShopFloor Configurator (`configurator`)** – end-user runtime experience that evaluates deployed rules.

## What changed

- Added a dedicated **Experience Studio** editor screen for mapping rules parameters to rich controls.
- Added **role segmentation**:
  - `admin/admin` has full access to all apps.
  - `ux-admin/ux-admin` can edit Experience Studio mappings.
- Added persistent UI mapping tables:
  - `ui_parameter_configs`
  - `ui_parameter_options`
- Added `/api/ui-schema` endpoint consumed by ShopFloor for control rendering.
- Kept **core product logic unchanged** in the editor screen (rules are still evaluated only by the rules engine runtime).

## Front-end mapping capabilities

Experience Studio supports per-parameter mapping for:

- Text input
- Number input
- Radio yes/no
- Slider with min/max/step
- Dropdown from predefined values
- Toggleable button group from predefined values
- Display style variants (`classic`, `card`, `accent`, `pill`, `tile`)
- Parameter-level image URLs
- Value-level image URLs
- UI required flag and help text

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Run services (shared DB):

```bash
python -m sales_configurator landing --port 8000 --db ./data.db
python -m sales_configurator rules --port 8001 --db ./data.db
python -m sales_configurator configurator --port 8002 --db ./data.db
python -m sales_configurator experience --port 8003 --db ./data.db
```

## Authentication

- Admin (all apps): `admin/admin`
- Experience editor: `ux-admin/ux-admin`

## Wiki

- [Configuration Engine Wiki](docs/configuration-engine-wiki.md)
- [Experience Studio Wiki](docs/experience-studio-wiki.md)

## Tests

```bash
pytest
```
