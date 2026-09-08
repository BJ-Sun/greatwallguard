# Graph-state summary experiment plan

This document is the plan for the "freeze process graph and validate bounded
graph-state summaries" experiment. It fixes the process layer, defines the new
bounded summary schema and its budgets, and states the evaluation protocol.

> Status 2026-09-07: the plan was implemented and run. The offline
> compression/coverage matrix is saved in `experiments/graph_summary_20260907/`
> with `results.json`, per-checkpoint graphs/content/views, source oracles and a
> `SUMMARY.md`. A live OpenClaw smoke was attempted but stopped before any turn
> because the DeepSeek probe returned HTTP 402 (see
> `experiments/graph_summary_20260907/live/status.json`).

## 1. Frozen process layer (do not redesign)

The process schema is frozen at `docs/REPRESENTATION_SPEC.md` and implemented in
`src/greatwallguard` (`model.py`, `graph.py`, `runtime.py`,
`agentlab_recorder.py`). We keep, unchanged:

- Node semantics: `Observation` / `Action` / `Effect` / `State`.
- Edge semantics: `derived_from`, `causes`, `updates`, `reads`, `next`, each
  carrying `basis` (`observed|reported|declared|inferred|unspecified`) +
  `method` evidence.
- Per-node fields: `source`/`integrity`/`object_id` for observations; `tool`,
  `arguments_digest`, `call_id`, `decision`, `execution_status` for actions;
  `kind`, `target`, `operation`, `persistent`, `reversible`, `status`,
  `source_node_ids` for effects; `object_id`, `version`, `effect_id`, `kind`,
  `fingerprint` (SHA-256 of file content) and commit evidence for states.
- The finite Effect vocabulary (`read|write|create|delete|send|execute|
  permission_change|unknown`) and `StateTransition` fingerprint scoping.

The full audit graph remains lossless with evidence references. The new runtime
summary is a bounded **view of the same graph** and never replaces it. No new
node types, no whitelist/blacklist semantics, no attack rules, no benign/malicious
classification.

## 2. Bounded graph-state summary

New module: `src/greatwallguard/state_summary.py`. It reads the **saved** audit
record (the `trace_dict()` envelope: `graph` nodes/edges/state_versions plus the
`events` trace) and the content index raw texts, and emits a serializable summary
with four bounded components:

1. `recent_trace` — the exact most recent process events and their IDs (a count
   bound; event records are copied verbatim, never reworded or merged).
2. `effect_ledger` — deduplicated **live** persistent states/effects: one entry
   per object with its latest committed version, fingerprint/hash, effect kind,
   and evidence references (state node id, effect id, commit evidence basis/method,
   source node ids). Older versions and over-budget objects are represented by
   counts and a digest of omitted object ids.
3. `effect_process_ledger` — persistent Effects joined to their producing
   action/call, argument digest, source integrity, result evidence and State
   version. Failed persistent attempts without a State are retained.
4. `content_sketch` — task-relevant facts, constraints, conditions, revisions and
   retractions with evidence references, not raw full documents. Two modes:
   - **LLM mode** (optional): an explicit prompt + output schema; every
     proposition must cite a source record id and a verbatim-unique quote span.
     Schema-invalid or quote-unsupported claims are rejected and counted. A call
     failure or unparseable response is recorded as `unknown` and never invents
     text.
   - **Deterministic extractive fallback** (always available): keeps whole
     paragraph evidence units with source ref + char positions + original text,
     exactly like `extractive.py`.

Configurable budget: `max_events` (recent trace), `max_ledger_objects` +
`max_sources_per_object` (ledger), `max_process_ledger_entries` (process ledger),
`sketch_budget_bytes` (content sketch). Three
preset levels are used for the comparison matrix:

| level | max_events | max_ledger_objects | max_sources | sketch bytes |
|---|---|---|---|---|
| small | 6 | 8 | 3 | 1024 |
| medium | 12 | 16 | 4 | 4096 |
| large | 20 | 32 | 6 | 16384 |

Determinism & replay: `json_bytes` sorts keys so serialization is deterministic.
The LLM raw response is cached by content ref + prompt version; replay calls
`summarize(..., model_fn=None, response_cache=<saved>)` and re-validates the
cached response, so the summary is reproduced from the saved audit graph **without
another API call**.

## 3. Real OpenClaw experiments

Three normal long-task families, each ≥30 real user turns (or the largest safe
number allowed by the API budget), checkpoints at 10/20/30, all tools inside a
freshly created isolated directory (only `read_file` / `write_file` /
`list_files`; no network/email/db/production writes):

- `multifile` — maintain facts across several files and produce a report
  (one continuous conversation).
- `revision` — accept changing recipients, conditions, approvals and
  withdrawals (fresh context each turn).
- `recovery` — cross-session recovery: reload files/memory, handle repeated and
  no-op writes and multiple growing objects (fresh context each turn).

The agent generates its own tool calls via the real local OpenClaw/AgentLAB
`VictimAgent` + DeepSeek client (the same path used by
`experiments/longrun_driver.py`). At least `multifile` is one continuous
conversation; `recovery` performs a real cross-session reconstruction (each turn
re-reads `MEMORY.md` and object files). Completed prefixes are never re-run:
resume rebuilds the recorder from the saved oracle with zero API calls.

If the DeepSeek account is out of credit (the prior run halted on `402 Payment
Required`), the driver stops after three consecutive API failures, saves a
checkpoint, and the matrix is instead computed **offline** from the already-saved
real-agent audit graphs (`experiments/longrun_20260907/*`, `two_axis_v1/*`), which
are genuine model-generated runs. This is documented explicitly rather than
presenting a replay as a fresh run.

## 4. Compression / coverage matrix

At each checkpoint (10/20/30) compare five views:

1. full audit graph + raw content;
2. fixed recent-window baseline (last N events only, no ledger, no sketch);
3. graph summary — small budget;
4. graph summary — medium budget;
5. graph summary — large budget.

Measured and saved machine-readable (per view, per checkpoint):

- graph byte size and runtime-view byte size; summary byte size;
- context tokens sent to the model and summarizer tokens/calls (from usage logs,
  chars/4 estimate when usage is absent);
- compression ratio vs full audit representation;
- process event recall/precision by call id, arguments, returns and state hashes
  (which of the oracle call ids / args digests / returns / state fingerprints
  survive in the view);
- persistent-effect coverage and live-state/version consistency (is each live
  object present with the correct latest version + fingerprint?);
- content coverage for facts, negation, conditions, revisions, retractions
  (gold strings derived before selection from the deterministic task scripts,
  never leaked into the summarizer prompt; measured as retention of the exact
  gold spans plus an optional LLM reader);
- summary evidence-support rate and unknown/unsupported-proposition rate;
- replay/reconstruction equality (rebuild from saved graph + cached responses,
  byte-compare);
- task-completion quality (family `task_outcomes` against the script's required
  files — kept separate from representation coverage);
- per-turn latency and API usage.

Representation coverage is reported separately from task success.

## 5. Budgets, safety, deliverables

Hard limits for this experiment: 300 API requests, 6M input tokens, 500k output
tokens, 2h wall clock. Serial execution; after three consecutive API failures the
driver saves a checkpoint and stops; billing errors are not retried indefinitely.
The DeepSeek `.env` is used at runtime only and credentials are never printed.

Deliverables:

- `experiments/graph_summary_YYYYMMDD/` with isolated task files, audit graphs,
  summaries, raw model responses, metrics, checkpoints, logs;
- `status.json`, `results.json`, `SUMMARY.md`;
- this `experiments/GRAPH_SUMMARY_PLAN.md`;
- updated README/docs describing the implemented summary and its limits;
- `tests/test_state_summary.py` for bounds, evidence references,
  unsupported-claim rejection, deterministic fallback, and replay.
