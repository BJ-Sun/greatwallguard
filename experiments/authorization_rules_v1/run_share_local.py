#!/usr/bin/env python3
"""Pre-call share_file rule replay on three frozen real OpenClaw sessions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))

from greatwallguard.authorization_rules import ConservativeLocalExtractor, ToolEnvironment  # noqa: E402
from greatwallguard.native_openclaw_graph import read_native_events  # noqa: E402
from greatwallguard.online_auditor import StreamingAuditor  # noqa: E402


SELECTED = (
    ("S-T0-SYNTH-direct-user-rw-control", "explicit_authorized_share",
     WORKSPACE / "openclaw-longrange-lab/dataset/share-file/runs/S-T0-SYNTH-direct-user-rw-control"),
    ("S-T0-CONTROL-direct-user-rw", "unauthorized_share_after_read_request",
     WORKSPACE / "openclaw-longrange-lab/dataset/share-file/runs/S-T0-CONTROL-direct-user-rw"),
    ("GWG-N-SHARE-001", "normal_share_with_unspecified_parameters",
     ROOT / "dataset/benign-controls/raw-runs/GWG-N-SHARE-001"),
)


def replay(case_id: str, analysis_group: str, base: Path) -> dict:
    case = json.loads((base / "cases" / f"{case_id}.json").read_text(encoding="utf-8"))
    environment = ToolEnvironment.from_tool_schemas(
        case["tool_contract"]["tools"],
        {"share_file": {"effect": "share_file",
                        "critical_fields": ["file_id", "email", "permission"]}})
    if environment.by_name("share_file") is None:
        raise ValueError(f"{case_id}: share_file absent from runtime schema")
    auditor = StreamingAuditor(environment, ConservativeLocalExtractor())
    by_turn: dict[int, list[dict]] = {}
    for item in case.get("execution", {}).get("workspace_event_trace") or []:
        by_turn.setdefault(int(item["turn"]), []).append(item)
    db = base / "openclaw-state/agents/main/agent/openclaw-agent.sqlite"
    for seq, event in read_native_events(db):
        if (event.get("type") == "message" and (event.get("message") or {}).get("role") == "user"
                and auditor.graph.current_turn > 0):
            for item in by_turn.pop(auditor.graph.current_turn, []):
                auditor.graph.ingest_workspace_snapshot(item)
        auditor.ingest(seq, event)
    for item in by_turn.pop(auditor.graph.current_turn, []):
        auditor.graph.ingest_workspace_snapshot(item)
    if by_turn:
        raise ValueError(f"{case_id}: snapshot references absent user turn")
    before, after = case["execution"].get("state_before"), case["execution"].get("state_after")
    if isinstance(before, dict) and isinstance(after, dict):
        auditor.graph.ingest_external_state_diff(before, after)
    auditor.graph.assert_complete_process()
    return {"case_id": case_id, "analysis_group_not_given_to_extractor": analysis_group,
            "user_turns": len(auditor.ledger.user_messages),
            "grants": auditor.ledger.as_dict()["grants"],
            "unresolved": auditor.ledger.as_dict()["unresolved"],
            "decisions": [{"turn": row["turn"], "tool": row["tool"],
                           "arguments": row["arguments"], "verdict": row["verdict"],
                           "reason": row["reason"], "grant_id": row["grant_id"]}
                          for row in auditor.decisions],
            "extraction_errors": auditor.extraction_errors,
            "process_coverage": auditor.graph.coverage()}


if __name__ == "__main__":
    output = Path(__file__).with_name("share_local_replay_results.json")
    if output.exists():
        raise FileExistsError(output)
    result = {"schema": "gwg-authorization-share-replay-v1",
              "extractor": "conservative_local_grammar",
              "rows": [replay(*item) for item in SELECTED]}
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps([{"case_id": row["case_id"], "decisions": row["decisions"]}
                      for row in result["rows"]], ensure_ascii=False, indent=2))
