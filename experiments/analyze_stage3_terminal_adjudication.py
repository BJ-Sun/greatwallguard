#!/usr/bin/env python3
"""Merge binary terminal adjudications into the proof-obligation task results."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from greatwallguard import TerminalAdjudication, TerminalAdjudicationPolicy


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "experiments" / "stage3_proof_obligation"
TERMINAL = ROOT / "experiments" / "stage3_terminal_adjudication"


def analyze() -> dict:
    tasks = json.loads((PROOF / "task_analysis.json").read_text(encoding="utf-8"))
    calls = {row["record_id"]: row for row in json.loads(
        (TERMINAL / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    policy = TerminalAdjudicationPolicy()
    by_task: dict[tuple, list[str]] = {}
    for record_id, row in calls.items():
        parts = record_id.split(":")
        key = (parts[0], parts[1], parts[2], parts[3], None if parts[4] == "none" else parts[4])
        decision = TerminalAdjudication.from_mapping(row["decision"])
        by_task.setdefault(key, []).append(policy.resolve(decision).value)

    rows = []
    for row in tasks["rows"]:
        final = row["final"]
        terminal_calls = []
        if final == "review":
            key = (
                row["benchmark"], row["group"], row["suite"], row["task_id"],
                row.get("injection_task_id"),
            )
            terminal_calls = by_task.get(key, [])
            final = (
                "deny" if "deny" in terminal_calls or not terminal_calls else
                "confirm" if "confirm" in terminal_calls else "allow"
            )
        elif final == "alert":
            final = "deny"
        rows.append({**row, "terminal": final, "terminal_call_verdicts": terminal_calls})

    counts = Counter((r["benchmark"], r["group"], r["terminal"]) for r in rows)
    effective = Counter(
        (r["benchmark"], r["terminal"])
        for r in rows if r["group"] == "attack" and r["has_target"]
    )
    output = {
        "schema": "greatwallguard-stage3-terminal-binary-task-results-v1",
        "summary": [
            {"benchmark": k[0], "group": k[1], "outcome": k[2], "count": v}
            for k, v in sorted(counts.items())
        ],
        "effective_attack_summary": [
            {"benchmark": k[0], "outcome": k[1], "count": v}
            for k, v in sorted(effective.items())
        ],
        "rows": rows,
    }
    (TERMINAL / "task_analysis.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return output


if __name__ == "__main__":
    value = analyze()
    print(json.dumps({
        "summary": value["summary"],
        "effective_attack_summary": value["effective_attack_summary"],
    }, ensure_ascii=False, indent=2))
