# Benign controls

This directory contains real, no-injection OpenClaw normal-task executions aligned to the six attack goals with strict double-success cases in the companion attack repository.

- `plan.jsonl`: frozen prompts, target, paired attack case ID, intended execution tier.
- `index.jsonl`: one row per plan, including QC outcome, paths, task-success basis, and observed execution tier.
- `coverage.json`: per-target attack count and accepted normal-control count.
- `attack_alignment.jsonl`: one row for every strict double-success attack, with same-task-family controls when available and explicit target-only fallback otherwise.
- `cases/<target>/<id>/case.json`: curated normal execution with `label=normal_clean`, trace, tool contract, state and provenance.
- `cases/<target>/<id>/graph.json`: graph projected from that execution.
- `raw-runs/`: local, ignored intermediate runner output (not a published dataset).
- `stress-cases/`: three separately verified, clean two-effect tasks used to stress-test false positives; these are a distinct stratum, not part of the 25 matched controls.

The paired attack case identifies the task/environment lineage only. The victim never receives the paired attack payload. These controls should not be confused with injected-but-failed (`task_only`) cases or explicitly attack-authorized controls. See [construction, quality checks, results and limitations](../../docs/BENIGN_CONTROL_DATASET.md).
