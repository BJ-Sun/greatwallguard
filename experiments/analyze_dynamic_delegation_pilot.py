#!/usr/bin/env python3
"""Overlay delegation-aware pilot decisions on terminal task outcomes."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TERMINAL = ROOT / "experiments" / "stage3_terminal_adjudication" / "task_analysis.json"
PILOT = ROOT / "experiments" / "dynamic_delegation_pilot" / "results_v2.json"
OUT = ROOT / "experiments" / "dynamic_delegation_pilot" / "task_analysis_v2.json"


def analyze() -> dict:
    tasks = json.loads(TERMINAL.read_text())["rows"]
    calls = json.loads(PILOT.read_text())["rows"]
    by_task: dict[tuple, list[str]] = {}
    for row in calls:
        key = (row["benchmark"], row["group"], row["suite"], row["task_id"], None)
        by_task.setdefault(key, []).append(str(row["prediction"]["verdict"]).casefold())
    output_rows = []
    for row in tasks:
        key = (row["benchmark"], row["group"], row["suite"], row["task_id"], row.get("injection_task_id"))
        final = row["terminal"]
        if key in by_task:
            values = by_task[key]
            final = "deny" if "deny" in values else "confirm" if "confirm" in values else "allow"
        output_rows.append({**row, "dynamic_delegation_terminal": final})
    counts = Counter((r["benchmark"], r["group"], r["dynamic_delegation_terminal"]) for r in output_rows)
    effective = Counter(
        (r["benchmark"], r["dynamic_delegation_terminal"])
        for r in output_rows if r["group"] == "attack" and r["has_target"]
    )
    output = {
        "schema": "greatwallguard-dynamic-delegation-task-overlay-v1",
        "summary": [
            {"benchmark": k[0], "group": k[1], "outcome": k[2], "count": v}
            for k, v in sorted(counts.items())
        ],
        "effective_attack_summary": [
            {"benchmark": k[0], "outcome": k[1], "count": v}
            for k, v in sorted(effective.items())
        ],
        "rows": output_rows,
    }
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    return output


if __name__ == "__main__":
    result = analyze()
    print(json.dumps({"summary": result["summary"], "effective_attack_summary": result["effective_attack_summary"]}, ensure_ascii=False, indent=2))
