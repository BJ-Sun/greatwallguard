# GreatWallGuard compiler overview visual audit

## Visible-element inventory

| ID | Region | Content / medium | Style | Status |
|---|---|---|---|---|
| title | top | method title / native text | 26pt navy | accepted |
| compile_panel | upper-left | authorization compilation / native panel | light blue, rounded | accepted |
| user_input | upper-left | trusted user request / native card | white, blue border | accepted |
| schema_input | upper-left | tool schema / native card | white, blue border | accepted |
| compiler | upper-middle | LLM front-end and type checker / native card | blue | accepted |
| auth_ir | upper-right | finite Authorization IR / native card | blue border | accepted |
| stdlib | under IR | finite operator library / native card | dashed blue | accepted |
| new_user | upper-right | incremental update / native card | green | accepted |
| runtime_panel | lower-left | online execution / native panel | neutral gray | accepted |
| agent | lower-left | black-box agent / native card | white | accepted |
| monitor | lower-middle | host-side monitor / native card | gray | accepted |
| fact_graph | lower-right | execution fact graph / native card | gray border | accepted |
| effect_gate | lower-right | pending effect / native card | orange | accepted |
| verifier | right-center | proof verifier / native card | green emphasis | accepted |
| outcomes | right-lower | PROVED / UNKNOWN / DENIED / native cards | green/yellow/red | accepted |
| longrange | bottom-right | version-chain check / native card | purple | accepted |
| connectors | all panels | orthogonal workflow arrows / native connectors | semantic colors, 2px | accepted |

## Quality checks

- Editable structure and text: accepted.
- Color is reinforced by labels; no color-only encoding: accepted.
- Minimum body font is 11pt before paper scaling; export should retain at least 8pt: accepted.
- No raster artwork or generic substitute icons: accepted.
- No chartjunk or decorative elements unrelated to the method: accepted.
- PNG export visually inspected at 1600×920: no clipped text, missing cards, or ambiguous workflow connectors; accepted.
