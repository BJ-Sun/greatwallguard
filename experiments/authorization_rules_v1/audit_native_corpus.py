#!/usr/bin/env python3
"""Corpus-level process coverage audit; no model calls and no case labels."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
from greatwallguard.native_openclaw_graph import build_native_graph  # noqa: E402


def run() -> dict:
    dbs = sorted((WORKSPACE / "openclaw-longrange-lab/dataset").rglob("openclaw-agent.sqlite"))
    dbs += sorted((ROOT / "dataset/benign-controls/raw-runs").rglob("openclaw-agent.sqlite"))
    totals: Counter[str] = Counter()
    suites: dict[str, Counter[str]] = defaultdict(Counter)
    unknown_tools: Counter[str] = Counter()
    incomplete: list[dict] = []
    failures: list[dict] = []
    known_tool_dispatch_complete = 0
    for index, db in enumerate(dbs, 1):
        suite = db.parts[db.parts.index("dataset") + 1]
        case_id = db.parents[4].name
        try:
            builder = build_native_graph(db)
            report = builder.coverage()
        except Exception as error:
            failures.append({"case_id": case_id, "suite": suite,
                             "error_type": type(error).__name__, "error": str(error)[:160]})
            continue
        try:
            builder.assert_known_tool_dispatch_coverage()
        except ValueError:
            pass
        else:
            known_tool_dispatch_complete += 1
        totals.update({"sessions": 1, "native_events": report["native_events"],
                       "native_events_with_audit_anchor": report["native_events_with_audit_anchor"],
                       "tool_calls": report["tool_calls"], "tool_result_events": report["tool_result_events"],
                       "paired_tool_results": report["paired_tool_results"],
                       "orphan_result_events": len(report["orphan_results"]),
                       "orphan_failed_dispatch": len(report["orphan_failed_dispatch"]),
                       "orphan_unclassified": len(report["orphan_unclassified"]),
                       "unpaired_calls": len(report["unpaired_calls"]),
                       "workspace_file_writes": report["file_writes"],
                       "cloud_mutations": report["cloud_mutations"],
                       "parameter_candidate_edges": report["parameter_candidate_edges"],
                       "unknown_effect_calls": len(report["unknown_effect_calls"])})
        suites[suite].update({"sessions": 1, "tool_calls": report["tool_calls"],
                              "tool_result_events": report["tool_result_events"],
                              "paired_tool_results": report["paired_tool_results"],
                              "workspace_file_writes": report["file_writes"],
                              "cloud_mutations": report["cloud_mutations"]})
        unknown_tools.update(builder.calls[item]["tool"] for item in report["unknown_effect_calls"])
        issues = {key: report[key] for key in
                  ("unpaired_calls", "orphan_results", "duplicate_call_ids",
                   "malformed_messages", "unknown_effect_calls") if report[key]}
        if report["native_events_with_audit_anchor"] != report["native_events"]:
            issues["unanchored_native_events"] = (report["native_events"]
                                                 - report["native_events_with_audit_anchor"])
        if issues:
            incomplete.append({"case_id": case_id, "suite": suite, "issues": issues})
        if index % 100 == 0:
            print(f"audited {index}/{len(dbs)} sessions", file=sys.stderr, flush=True)
    return {"schema": "gwg-native-process-corpus-audit-v1", "scope": "retained OpenClaw session databases",
            "db_files": len(dbs), "totals": dict(totals),
            "complete_process_sessions": totals["sessions"] - len(incomplete),
            "known_tool_dispatch_complete_sessions": known_tool_dispatch_complete,
            "by_suite": {name: dict(counts) for name, counts in sorted(suites.items())},
            "unknown_tool_effects": dict(unknown_tools),
            "incomplete_sessions": incomplete, "failed_to_parse": failures,
            "interpretation": "Call/result coverage is directly observed; candidate-value edges do not establish semantic causality."}


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
