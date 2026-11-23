#!/usr/bin/env python3
"""Validate and freeze the GreatWallBench evaluation inventory."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from dataset_adapter import BENCHMARK_ROOT, iter_cases


HERE = Path(__file__).resolve().parent
OUT = HERE / "inventory.json"


def main() -> dict:
    rows = []
    counts = Counter()
    tools: dict[str, Counter] = defaultdict(Counter)
    task_fingerprints = Counter()
    errors = []
    for case in iter_cases():
        counts[(case.label.group, case.label.target)] += 1
        trusted_text = "\n".join(case.trusted_messages)
        fingerprint = hashlib.sha256(trusted_text.encode()).hexdigest()
        task_fingerprints[(case.label.group, fingerprint)] += 1
        calls = [event for event in case.events if event.kind == "tool_call"]
        for event in calls:
            tools[case.label.group][str(event.payload["tool"])] += 1
        if not case.trusted_messages:
            errors.append({"case_id": case.case_id, "error": "missing_trusted_message"})
        if not calls:
            errors.append({"case_id": case.case_id, "error": "missing_tool_calls"})
        if not case.tool_contract.get("tools"):
            errors.append({"case_id": case.case_id, "error": "missing_tool_contract"})
        if (case.label.group == "attack"
                and case.label.target != "model_output_integrity"
                and not case.label.target_call_ids):
            errors.append({"case_id": case.case_id, "error": "target_call_not_matched"})
        rows.append({
            "case_id": case.case_id,
            "group": case.label.group,
            "target": case.label.target,
            "source_path": str(case.source_path.relative_to(BENCHMARK_ROOT)),
            "trusted_message_sha256": fingerprint,
            "trusted_message_count": len(case.trusted_messages),
            "tool_call_count": len(calls),
            "state_event_count": sum(
                event.kind in {"state_read", "state_change"} for event in case.events
            ),
            "task_success": case.label.task_success,
            "attack_success": case.label.attack_success,
            "target_call_count": len(case.label.target_call_ids),
        })
    summary = {
        "cases": len(rows),
        "normal_cases": sum(row["group"] == "normal" for row in rows),
        "attack_cases": sum(row["group"] == "attack" for row in rows),
        "unique_normal_requests": len({
            row["trusted_message_sha256"] for row in rows if row["group"] == "normal"
        }),
        "unique_attack_requests": len({
            row["trusted_message_sha256"] for row in rows if row["group"] == "attack"
        }),
        "by_group_target": {
            f"{group}:{target}": count
            for (group, target), count in sorted(counts.items())
        },
        "tool_calls_by_group": {
            group: dict(counter.most_common()) for group, counter in tools.items()
        },
        "validation_errors": len(errors),
    }
    result = {
        "schema": "greatwallbench-defense-inventory-v1",
        "protocol": (
            "strict double-success attacks and curated successful normal controls; "
            "labels/oracles excluded from defense inputs"
        ),
        "summary": summary,
        "validation_errors": errors,
        "rows": rows,
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(2)
    return result


if __name__ == "__main__":
    main()
