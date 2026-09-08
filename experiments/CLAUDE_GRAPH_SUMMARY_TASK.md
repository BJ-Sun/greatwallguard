# Claude task: freeze process graph and validate bounded graph-state summaries

Work only in `/Users/wenxiang/Documents/codexwork/longattackdefense/greatwallguard`.
The user explicitly asks you to implement and run this task, not merely propose a plan.
Preserve all existing uncommitted work and old experiments. Do not reset, clean, commit,
push, modify other repositories, or print/copy any API key. Use the existing
`../attack-generation/openclaw-agentlab/.env` only at runtime when the experiment needs
the DeepSeek API.

## Research question

We now freeze the process-layer graph and want to test a real long-running OpenClaw
agent across different normal task scenarios. The question is: how much can a bounded
graph-state summary reduce runtime context/storage while preserving observable events,
persistent effects, task-relevant content, and cross-turn state? This is a representation
experiment, not an attack detector. Do not add attack rules or classify content as benign
or malicious.

## Process layer: freeze, do not redesign

Treat the current process schema in `docs/REPRESENTATION_SPEC.md` and `src/greatwallguard`
as fixed for this experiment. Keep the existing O/A/E/S node and edge semantics,
source/evidence fields, call IDs, tool arguments/returns, state versions and hashes,
and effect types. Fix bugs only when needed for faithful capture; add regression tests.
Do not introduce scenario-specific node types or a new whitelist/blacklist semantics.

The full audit graph remains lossless with evidence references. The new runtime summary
must be a bounded view of the same graph and must never replace the audit graph.

## Implement a first real graph-state summarizer

Add a small, documented module (for example `src/greatwallguard/state_summary.py`) and
tests. It should maintain three bounded components:

1. `recent_trace`: exact recent process events and their IDs;
2. `effect_ledger`: deduplicated live persistent states/effects (files, memory, config,
   permissions and external side effects), with version/hash and evidence references;
3. `content_sketch`: task-relevant facts, constraints, conditions and revisions with
   evidence references, not raw full documents.

The first content summarizer may call the existing DeepSeek-compatible OpenAI API. Keep
the prompt and output schema explicit, require every proposition to cite source event or
paragraph IDs, reject unsupported claims, and record failures as unknown rather than
inventing text. Add a deterministic fallback that keeps extractive evidence units.
Expose a configurable byte/token budget so the experiment can compare multiple budgets.
The summary must be serializable, deterministic given the model response, and replayable
from the saved audit graph without another API call.

## Real OpenClaw experiments

Inspect the current OpenClaw/AgentLAB integration first. Use the actual local OpenClaw
agent execution path and real model-generated tool calls, not a deterministic replay
presented as a real run. All tools must operate only inside a newly created isolated
experiment directory; no network sends, email, database writes or production files.
If a native OpenClaw path is genuinely unavailable, document the exact blocker and use
the closest existing AgentLAB OpenClaw adapter, clearly labeling it as such.

Run three different normal long-task families, each with at least 30 real user turns
(or the largest safe number allowed by the API budget), with checkpoints at 10/20/30:

* `multifile`: maintain facts across several files and produce a report;
* `revision`: accept changing requirements, recipients, conditions, and retractions;
* `recovery`: work across sessions, reload files/memory after failures, and handle
  repeated/no-op writes and multiple growing objects.

At least one family must be one continuous conversation; at least one must perform a
real context/session reconstruction. The agent must autonomously generate tool calls.
Do not count prewritten calls or replay as model interaction.

## Compression/coverage matrix

At each checkpoint compare at least:

* full audit graph/raw content;
* fixed recent-window baseline;
* graph summary with a small budget;
* graph summary with a medium budget;
* graph summary with a larger budget.

Measure and save machine-readable results for:

* graph byte size and runtime-view byte size;
* context tokens sent to the model and summarizer tokens/calls;
* compression ratio versus full audit representation;
* process event recall/precision by call ID, arguments, returns and state hashes;
* persistent-effect coverage and live-state/version consistency;
* content coverage/QA for facts, negation, conditions, revisions and retractions;
* summary evidence support rate and unknown/unsupported proposition rate;
* replay/reconstruction equality and task completion quality;
* per-turn latency and API usage.

Gold questions must be derived before selection from deterministic task facts and must
not be leaked into the summarizer prompt. Keep bad cases and explain them. Distinguish
representation coverage from task success.

## Budgets, safety and deliverables

Use the existing DeepSeek `.env` at runtime; never print credentials. Run serially with
hard limits of 300 experiment API requests, 6M input tokens, 500k output tokens and 2h.
After three consecutive API failures, save a checkpoint and stop. Do not retry billing
errors indefinitely. Make each turn/checkpoint resumable and never rerun completed
prefixes.

Deliver:

* `experiments/graph_summary_YYYYMMDD/` with isolated task files, audit graphs,
  summaries, raw model responses, metrics, checkpoints and logs;
* `status.json`, `results.json` and a concise `SUMMARY.md`;
* a short `experiments/GRAPH_SUMMARY_PLAN.md` explaining the frozen process layer,
  summary schema, budgets and evaluation protocol;
* updated README/docs only where needed to describe the implemented summary and its
  limits;
* tests for summary bounds, evidence references, unsupported-claim rejection,
  deterministic fallback, and replay from the audit graph.

The final summary must answer: what information survives at each budget, what is lost,
how graph size and model context scale with turns, whether process and persistent-effect
coverage remain stable, and the single most important next improvement. Do not claim
attack-detection ability from these normal-task runs.
