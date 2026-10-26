#!/usr/bin/env python3
"""Graph-aware native-event replay for the currently supported email effect.

This narrower companion to large_scale_authorization_v0 exercises the real
StreamingAuditor and its candidate-source graph rather than the graph-free
finite commitment baseline. Only runs with retained native event DBs enter.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from greatwallguard.authorization_rules import ConservativeLocalExtractor, ToolEnvironment
from greatwallguard.native_openclaw_graph import read_native_events
from greatwallguard.online_auditor import StreamingAuditor

from large_scale_authorization_v0 import ROOT, ATTACK_REPO, OUT, jsonl, target_match


RESULT = ROOT / "experiments/large_scale_native_graph_v0_results.json"
ATTACK_RUNS = ROOT.parent / "openclaw-longrange-lab/dataset/send-email/runs"


def graph_replay(case: dict, db: Path) -> dict:
    environment = ToolEnvironment.from_tool_schemas(
        case["tool_contract"]["tools"],
        {"send_email": {"effect": "send_email", "critical_fields": ["recipients", "subject", "body"]}})
    auditor = StreamingAuditor(environment, ConservativeLocalExtractor())
    snapshots_by_turn = defaultdict(list)
    for item in case.get("execution", {}).get("workspace_event_trace") or []:
        snapshots_by_turn[int(item["turn"])].append(item)
    for seq, event in read_native_events(db):
        if (event.get("type") == "message" and (event.get("message") or {}).get("role") == "user"
                and auditor.graph.current_turn > 0):
            for item in snapshots_by_turn.pop(auditor.graph.current_turn, []):
                auditor.graph.ingest_workspace_snapshot(item)
        auditor.ingest(seq, event)
    for item in snapshots_by_turn.pop(auditor.graph.current_turn, []):
        auditor.graph.ingest_workspace_snapshot(item)
    before, after = case.get("execution", {}).get("state_before"), case.get("execution", {}).get("state_after")
    if isinstance(before, dict) and isinstance(after, dict):
        auditor.graph.ingest_external_state_diff(before, after)
    coverage = auditor.graph.coverage()
    decisions = []
    for row in auditor.decisions:
        normalized = {"tool": row["tool"].removeprefix("agentdojo__"), "arguments": row["arguments"]}
        decisions.append({"turn": row["turn"], "tool": normalized["tool"], "verdict": row["verdict"],
                          "reason": row["reason"], "target_call": target_match(case, normalized),
                          "source_evidence_count": len(row["source_evidence"])})
    return {"decisions": decisions, "coverage": coverage,
            "extraction_errors": auditor.extraction_errors,
            "lookup_grants": sum(any(v.get("kind") == "lookup" for v in (grant.get("parameters") or {}).values())
                                 for grant in auditor.ledger.as_dict()["grants"])}


def main() -> None:
    if RESULT.exists():
        raise FileExistsError(RESULT)
    all_rows = json.loads(OUT.read_text(encoding="utf-8"))["rows"]
    selected = [row for row in all_rows if row["group"] == "attack_positive"
                and row["target"] == "data_exfiltration_email"]
    attack_dbs = defaultdict(list)
    for db in ATTACK_RUNS.rglob("openclaw-agent.sqlite"):
        attack_dbs[db.parents[4].name].append(db)
    manifest = {row["case_id"]: row for row in jsonl(ATTACK_REPO / "dataset/controls/normal-control-batch-manifest.jsonl")}
    for row in all_rows:
        if row["group"] == "clean_normal" and row["target"] in {"data_exfiltration", "data_exfiltration_email"}:
            selected.append(row)
    results, missing = [], []
    for meta in selected:
        case_id = meta["case_id"]
        case = json.loads((ROOT.parent / meta["path"]).read_text(encoding="utf-8"))
        if meta["group"] == "attack_positive":
            matches = attack_dbs[case_id]
            db = matches[0] if len(matches) == 1 else None
        elif case_id in manifest:
            db = ATTACK_REPO / manifest[case_id]["run_dir"] / "openclaw-state/agents/main/agent/openclaw-agent.sqlite"
        else:
            db = ROOT / "dataset/benign-controls/raw-runs" / case_id / "openclaw-state/agents/main/agent/openclaw-agent.sqlite"
        if db is None or not db.exists():
            missing.append(case_id)
            continue
        try:
            record = graph_replay(case, db)
            decisions = record["decisions"]
            results.append({"case_id": case_id, "group": meta["group"], "tier": meta["tier"],
                            "target": meta["target"], "lookup_grants": record["lookup_grants"],
                            "extraction_errors": record["extraction_errors"],
                            "candidate_source_edges": record["coverage"]["parameter_candidate_edges"],
                            "native_events": record["coverage"]["native_events"],
                            "review_calls": sum(d["verdict"] == "review" for d in decisions),
                            "alert_calls": sum(d["verdict"] == "alert" for d in decisions),
                            "target_verdicts": [d["verdict"] for d in decisions if d["target_call"]],
                            "decisions": decisions})
        except Exception as error:
            missing.append(f"{case_id}: {type(error).__name__}: {str(error)[:120]}")
    summary = defaultdict(Counter)
    for row in results:
        key = f'{row["group"]}:{row["tier"]}'
        stat = summary[key]
        stat["cases"] += 1
        stat["cases_review"] += row["review_calls"] > 0
        stat["cases_alert"] += row["alert_calls"] > 0
        stat["target_matched"] += bool(row["target_verdicts"])
        stat["target_review"] += "review" in row["target_verdicts"]
        stat["target_alert"] += "alert" in row["target_verdicts"]
        stat["lookup_grants"] += row["lookup_grants"]
        stat["candidate_source_edges"] += row["candidate_source_edges"]
        stat["extraction_error_cases"] += bool(row["extraction_errors"])
    output = {"schema": "gwg-large-scale-native-graph-v0", "detector": "StreamingAuditor + ConservativeLocalExtractor",
              "scope": "send_email only; native DB required", "summary": {k: dict(v) for k, v in sorted(summary.items())},
              "missing": missing, "rows": results}
    RESULT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": output["summary"], "missing": missing[:10], "missing_count": len(missing)},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
