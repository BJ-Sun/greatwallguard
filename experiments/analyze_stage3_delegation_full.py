#!/usr/bin/env python3
"""Merge Stage-3 semantic verdicts back into Stage-2 task decisions."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "stage3_delegation_full" / "manifest.json"
RESULTS = ROOT / "experiments" / "stage3_delegation_full" / "results.json"
OUTPUT = ROOT / "experiments" / "stage3_delegation_full" / "analysis.json"

SOURCES = {
    "agentdojo": ROOT / "experiments" / "stage2_full" / "agentdojo_results_delegation_v1.json",
    "agentdyn": ROOT / "experiments" / "stage2_delegation_v1" / "agentdyn_results.json",
}


def _calls(row: dict[str, Any], benchmark: str) -> list[dict[str, Any]]:
    return row["calls"] if benchmark == "agentdojo" else row["decisions"]


def _task_id(row: dict[str, Any], benchmark: str) -> str:
    return str(row["user_task_id"] if benchmark == "agentdojo" else row["task_id"])


def _record_id(benchmark: str, group: str, row: dict[str, Any], index: int) -> str:
    return ":".join((
        benchmark,
        group,
        row["suite"],
        _task_id(row, benchmark),
        str(row.get("injection_task_id", "none")),
        str(index),
    ))


def _task_outcome(call_verdicts: list[str]) -> str:
    if "alert" in call_verdicts:
        return "alert"
    if "review" in call_verdicts:
        return "review"
    return "allow"


def analyze() -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    manifest_by_id = {row["record_id"]: row for row in manifest["records"]}
    audit_by_id = {row["record_id"]: row for row in results["rows"]}
    task_rows = []

    for benchmark, source in SOURCES.items():
        data = json.loads(source.read_text(encoding="utf-8"))
        for group, rows in (("normal", data["normal_rows"]), ("attack", data["attack_rows"])):
            for row in rows:
                final_calls = []
                for index, call in enumerate(_calls(row, benchmark)):
                    original = call["verdict"]
                    final = original
                    resolution = "stage2"
                    if original == "review":
                        record_id = _record_id(benchmark, group, row, index)
                        item = manifest_by_id[record_id]
                        if item["category"] == "semantic":
                            prediction = audit_by_id[record_id]["prediction"]["verdict"]
                            final = {
                                "authorized": "allow",
                                "unauthorized": "alert",
                                "uncertain": "review",
                            }[prediction]
                            resolution = "semantic_audit"
                        elif item["category"] == "program":
                            final = "review"
                            resolution = "evidence_missing"
                        elif item["category"] == "confirmation":
                            final = "review"
                            resolution = "policy_confirmation"
                    final_calls.append({
                        "index": index,
                        "tool": call["tool"],
                        "stage2": original,
                        "final": final,
                        "resolution": resolution,
                    })
                task_rows.append({
                    "benchmark": benchmark,
                    "group": group,
                    "suite": row["suite"],
                    "task_id": _task_id(row, benchmark),
                    "injection_task_id": row.get("injection_task_id"),
                    "stage2_outcome": row["outcome"],
                    "final_outcome": _task_outcome([item["final"] for item in final_calls]),
                    "calls": final_calls,
                })

    task_counts = Counter(
        (row["benchmark"], row["group"], row["final_outcome"])
        for row in task_rows
    )
    transitions = Counter(
        (row["benchmark"], row["group"], row["stage2_outcome"], row["final_outcome"])
        for row in task_rows
    )
    audit_rows = results["rows"]
    unique_requests = sum(not row.get("reused_prediction") for row in audit_rows)
    output = {
        "schema": "greatwallguard-stage3-delegation-analysis-v1",
        "semantics": (
            "semantic authorized=>ALLOW, unauthorized=>ALERT, uncertain=>REVIEW; "
            "evidence_missing and policy_confirmation remain REVIEW; task ALERT dominates REVIEW dominates ALLOW"
        ),
        "api": {
            "call_level_records": len(audit_rows),
            "unique_api_requests": unique_requests,
            "cached_reuses": len(audit_rows) - unique_requests,
            "total_tokens": sum(
                int((row.get("usage") or {}).get("total_tokens") or 0)
                for row in audit_rows if not row.get("reused_prediction")
            ),
        },
        "task_outcomes": [
            {"benchmark": key[0], "group": key[1], "outcome": key[2], "count": value}
            for key, value in sorted(task_counts.items())
        ],
        "transitions": [
            {
                "benchmark": key[0], "group": key[1],
                "stage2": key[2], "final": key[3], "count": value,
            }
            for key, value in sorted(transitions.items())
        ],
        "task_rows": task_rows,
    }
    OUTPUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


if __name__ == "__main__":
    print(json.dumps(analyze(), ensure_ascii=False, indent=2))
