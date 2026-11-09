#!/usr/bin/env python3
"""Merge proof-obligation verdicts into task outcomes and report both raw and effective attacks."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "experiments" / "stage3_delegation_full"
CERT = ROOT / "experiments" / "stage3_conflict_certificate"
PROOF = ROOT / "experiments" / "stage3_proof_obligation"
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
        benchmark, group, row["suite"], _task_id(row, benchmark),
        str(row.get("injection_task_id", "none")), str(index),
    ))


def analyze() -> dict[str, Any]:
    manifest = {row["record_id"]: row for row in json.loads(
        (FULL / "manifest.json").read_text(encoding="utf-8")
    )["records"]}
    prior = {row["record_id"]: row for row in json.loads(
        (FULL / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    certificates = {row["record_id"]: row for row in json.loads(
        (CERT / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    proofs = {row["record_id"]: row for row in json.loads(
        (PROOF / "results.json").read_text(encoding="utf-8")
    )["rows"]}

    rows: list[dict[str, Any]] = []
    for benchmark, path in SOURCES.items():
        data = json.loads(path.read_text(encoding="utf-8"))
        for group, source_rows in (("normal", data["normal_rows"]), ("attack", data["attack_rows"])):
            for source in source_rows:
                call_verdicts = []
                for index, call in enumerate(_calls(source, benchmark)):
                    verdict = call["verdict"]
                    if verdict == "review":
                        rid = _record_id(benchmark, group, source, index)
                        old = prior[rid]["prediction"]["verdict"] if manifest[rid]["category"] == "semantic" else None
                        if old == "authorized":
                            verdict = "allow"
                        elif old == "unauthorized" and certificates[rid]["final_verdict"] == "contradicted":
                            verdict = "alert"
                        else:
                            proof = proofs[rid]["final_verdict"]
                            verdict = {"supported": "allow", "contradicted": "alert"}.get(proof, "review")
                    call_verdicts.append(verdict)
                final = "alert" if "alert" in call_verdicts else "review" if "review" in call_verdicts else "allow"
                has_target = bool(_calls(source, benchmark)) if group == "attack" else None
                rows.append({
                    "benchmark": benchmark,
                    "group": group,
                    "suite": source["suite"],
                    "task_id": _task_id(source, benchmark),
                    "injection_task_id": source.get("injection_task_id"),
                    "final": final,
                    "has_target": has_target,
                })

    counts = Counter((row["benchmark"], row["group"], row["final"]) for row in rows)
    effective = Counter(
        (row["benchmark"], row["final"])
        for row in rows if row["group"] == "attack" and row["has_target"]
    )
    output = {
        "schema": "greatwallguard-stage3-proof-obligation-task-results-v1",
        "summary": [
            {"benchmark": key[0], "group": key[1], "outcome": key[2], "count": value}
            for key, value in sorted(counts.items())
        ],
        "effective_attack_summary": [
            {"benchmark": key[0], "outcome": key[1], "count": value}
            for key, value in sorted(effective.items())
        ],
        "rows": rows,
    }
    (PROOF / "task_analysis.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return output


if __name__ == "__main__":
    result = analyze()
    print(json.dumps({
        "summary": result["summary"],
        "effective_attack_summary": result["effective_attack_summary"],
    }, ensure_ascii=False, indent=2))
