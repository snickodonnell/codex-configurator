# Experience Studio Wiki

Experience Studio is the dedicated UI-configuration editor that maps rule parameters to customer-facing controls.

## Purpose

Experience Studio lets a privileged role configure how each parameter appears in ShopFloor without modifying business logic, constraint expressions, or calculation formulas.

## Roles

- `admin`: full access (RuleCanvas + Experience Studio + ShopFloor + Launchpad Orbit)
- `ux-admin`: Experience Studio authoring access

## Data model

### `ui_parameter_configs`

Stores one mapping row per parameter:

- `parameter_name`
- `display_label`
- `help_text`
- `control_type` (`text`, `number`, `radio_boolean`, `slider`, `dropdown`, `button_group`)
- `display_style` (`classic`, `card`, `accent`, `pill`, `tile`)
- `min_value`, `max_value`, `step_value`
- `placeholder`
- `image_url`
- `value_image_mode`
- `is_required`

### `ui_parameter_options`

Stores predefined option rows:

- `parameter_name`
- `option_value`
- `option_label`
- `option_order`
- `image_url`

## APIs

### Experience Studio app

- `GET /api/mappings` – list all mappings with options
- `POST /api/mappings` – upsert one mapping and replace options for that parameter

### ShopFloor app

- `GET /api/ui-schema?environment=dev` – resolve deployed memo schema + apply UI mappings

## Workflow

1. Author and deploy rules in RuleCanvas.
2. Open Experience Studio and map parameters to control types/styles/options.
3. Open ShopFloor and load schema.
4. Evaluate + submit configurations.

## Important boundary

Experience Studio is a **presentation layer editor only**. Rule evaluation remains in the existing rules engine runtime (`evaluate_rules`) and deployment mechanism.
