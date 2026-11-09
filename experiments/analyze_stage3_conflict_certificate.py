#!/usr/bin/env python3
"""Merge validated Stage-3 certificates back into Stage-2 task outcomes."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE3 = ROOT / "experiments" / "stage3_delegation_full"
CERT = ROOT / "experiments" / "stage3_conflict_certificate"
SOURCES = {
    "agentdojo": ROOT / "experiments" / "stage2_full" / "agentdojo_results_delegation_v1.json",
    "agentdyn": ROOT / "experiments" / "stage2_delegation_v1" / "agentdyn_results.json",
}


def _calls(row: dict[str, Any], benchmark: str) -> list[dict[str, Any]]:
    return row["calls"] if benchmark == "agentdojo" else row["decisions"]


def _task_id(row: dict[str, Any], benchmark: str) -> str:
    return str(row["user_task_id"] if benchmark == "agentdojo" else row["task_id"])


def analyze() -> dict[str, Any]:
    manifest_path = STAGE3 / "manifest.json"
    if not manifest_path.exists():
        import stage3_delegation_full_eval as full
        full.build_manifest()
    manifest = {row["record_id"]: row for row in json.loads(
        manifest_path.read_text(encoding="utf-8")
    )["records"]}
    prior = {row["record_id"]: row for row in json.loads(
        (STAGE3 / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    certificates = {row["record_id"]: row for row in json.loads(
        (CERT / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    rows = []
    for benchmark, path in SOURCES.items():
        data = json.loads(path.read_text(encoding="utf-8"))
        for group, source_rows in (("normal", data["normal_rows"]), ("attack", data["attack_rows"])):
            for source in source_rows:
                task_id = _task_id(source, benchmark)
                verdicts = []
                for index, call in enumerate(_calls(source, benchmark)):
                    verdict = call["verdict"]
                    if verdict == "review":
                        record_id = ":".join((
                            benchmark, group, source["suite"], task_id,
                            str(source.get("injection_task_id", "none")), str(index),
                        ))
                        if manifest[record_id]["category"] == "semantic":
                            old = prior[record_id]["prediction"]["verdict"]
                            if old == "authorized":
                                verdict = "allow"
                            elif old == "unauthorized" and certificates[record_id]["final_verdict"] == "contradicted":
                                verdict = "alert"
                            else:
                                verdict = "review"
                    verdicts.append(verdict)
                final = "alert" if "alert" in verdicts else "review" if "review" in verdicts else "allow"
                rows.append({
                    "benchmark": benchmark, "group": group, "suite": source["suite"],
                    "task_id": task_id, "injection_task_id": source.get("injection_task_id"),
                    "final": final,
                })
    counts = Counter((row["benchmark"], row["group"], row["final"]) for row in rows)
    output = {
        "schema": "greatwallguard-stage3-conflict-certificate-task-results-v1",
        "summary": [
            {"benchmark": key[0], "group": key[1], "outcome": key[2], "count": value}
            for key, value in sorted(counts.items())
        ],
        "rows": rows,
    }
    (CERT / "task_analysis.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return output


if __name__ == "__main__":
    print(json.dumps(analyze()["summary"], ensure_ascii=False, indent=2))
