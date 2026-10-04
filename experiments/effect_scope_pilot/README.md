# Frozen pilot outputs

- `pairs.jsonl`: 25 deterministic same-target, same-task-family attack/control pairs.
- `summary.json`: 25-pair comparison for Effect-kind and Precise-v0.
- `full_attack_audit.json`: exploratory breadth audit over all 305 double-success attacks.
- `stress_summary.json`: false positives on three real, no-injection, two-effect normal tasks.

The detailed per-case outputs and raw OpenClaw runs are local-only and ignored by Git; rerun `experiments/effect_scope_pilot.py` with the companion attack repository to regenerate them. The method and interpretation are in [`docs/EFFECT_SCOPE_PILOT.md`](../../docs/EFFECT_SCOPE_PILOT.md).
