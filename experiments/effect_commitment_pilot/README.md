# Request-side commitment pilot

`request_only.jsonl` is the 53-case annotation view: user messages in order plus tool names, without labels, execution traces, graph results or case paths. `evaluation_mapping.jsonl` is a separate offline join key and **must not be supplied to an annotator**.

`reference_draft.json` covers ten request sequences. It is an assistant-reviewed draft, **not independent human gold**. `local_candidates.jsonl` contains conservative deterministic proposals for all 53 sequences. The summary/result files compare the draft and candidates with observed persistent tool Effects; they do not establish production detection rates.

See [protocol and interpretation](../../docs/EFFECT_COMMITMENT_PILOT.md). External LLM annotation of these request texts was not authorized, so this experiment uses only local processing.
