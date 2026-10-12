#!/usr/bin/env python3
"""Analyze frozen visible user requests separately from graph features.

This reports exact request-sequence overlap, not semantic authorization labels.
It never reads attack plans, target effects, graph verdicts, or tool results.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
FEATURES = HERE / "case_features_reprojected.jsonl"


def digest(messages: list[str]) -> str:
    value = json.dumps(messages, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def main() -> None:
    features = [json.loads(line) for line in FEATURES.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = []
    for item in features:
        source = WORKSPACE / item["source_path"]
        case_path = source if source.name != "graph.json" else source.parent / "case.json"
        case = json.loads(case_path.read_text(encoding="utf-8"))
        messages = [str(turn.get("user_message")) for turn in (case.get("execution") or {}).get("visible_agent_turns") or []
                    if turn.get("user_message")]
        rows.append({"case_id": item["case_id"], "cohort": item["cohort"],
                     "message_count": len(messages), "sequence_digest": digest(messages)})
    by_cohort = {}
    for cohort in sorted({row["cohort"] for row in rows}):
        subset = [row for row in rows if row["cohort"] == cohort]
        by_cohort[cohort] = {
            "cases": len(subset),
            "message_count_distribution": dict(sorted(Counter(row["message_count"] for row in subset).items())),
            "unique_exact_request_sequences": len({row["sequence_digest"] for row in subset}),
        }
    by_digest: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_digest[row["sequence_digest"]].append(row)
    shared_success_failure = [{"sequence_digest": key, "case_ids": [row["case_id"] for row in group]}
                              for key, group in by_digest.items()
                              if any(row["cohort"] == "attack_double_success" for row in group)
                              and any(row["cohort"].startswith("attack_failed") for row in group)]
    result = {
        "schema": "gwg-email-user-request-posthoc-v0",
        "input": "execution.visible_agent_turns[].user_message only",
        "cohorts": by_cohort,
        "exact_request_sequences_shared_by_success_and_failure": shared_success_failure,
        "note": "These are experiment-scripted user messages; trusted-user provenance is not established by this audit.",
    }
    (HERE / "user_request_summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
