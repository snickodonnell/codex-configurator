# Experience Studio Wiki

Experience Studio is the governed UX mapping stage between RuleCanvas authoring and ShopFloor runtime consumption.

## End-to-end process

1. Rules are authored/updated in **RuleCanvas**.
2. Rule save computes a fingerprint and sets workflow to `draft`.
3. Release is sent to Studio (`in_studio`).
4. UX editor maps rule parameters to allowed controls.
5. Workflow moves to `pending_approval` and then `approved`.
6. Approved release can be deployed and consumed by ShopFloor.

## Governance model

Studio reads `ruleset_parameter_profiles` per ruleset and enforces allowed control types:

- boolean → `radio_boolean`, `dropdown`, `button_group`
- number → `number`, `slider`, `dropdown`, `button_group`
- string → `text`, `dropdown`, `button_group`
- intermediate → `text`

If a mapping violates governance, the API rejects it.

## Mandatory UX updates

Rules changes update a fingerprint. If changed compared to prior release lineage, workflow is marked `requires_ux_update=1`.

While this flag is set:

- approval is blocked
- deployment is blocked

Saving Studio mappings clears the flag and increments `ux_schema_version`.

## Data model

- `release_workflows`: state machine + UX sync requirement.
- `ruleset_parameter_profiles`: per-ruleset governance controls.
- `ui_parameter_configs`: mapping row scoped to `ruleset_id`.
- `ui_parameter_options`: value options scoped to `ruleset_id`.
- `ui_schema_history`: version history for Studio edits.
- `deployment_history`: deployment and rollback audit trail.

## APIs

### Studio

- `GET /api/mappings?ruleset_id=<id>`
- `POST /api/mappings`
- `GET /api/schema-history?ruleset_id=<id>`

### Rules workflow

- `POST /workflow/<ruleset_id>/send-to-studio`
- `POST /workflow/<ruleset_id>/request-approval`
- `POST /workflow/<ruleset_id>/approve`
- `POST /deploy/<ruleset_id>`
- `POST /rollback`

### ShopFloor runtime

- `GET /api/ui-schema?environment=...`

ShopFloor applies deployed ruleset mappings only; core rules computation is still done by the rules engine.
