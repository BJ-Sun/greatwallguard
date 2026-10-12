#!/usr/bin/env python3
"""Request-only DeepSeek extraction plus pre-send replay on frozen real runs.

Only trusted user messages, active grants, and a finite tool environment are
sent to the model. Raw tool results, attack labels, graphs, and oracles are not.
The native graph is built locally and deterministically from retained events.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))

from greatwallguard.authorization_rules import (  # noqa: E402
    EXTRACTOR_SYSTEM_PROMPT, ConservativeLocalExtractor,
    ToolEnvironment,
)
from greatwallguard.native_openclaw_graph import read_native_events  # noqa: E402
from greatwallguard.online_auditor import StreamingAuditor  # noqa: E402


NORMAL_IDS = ("GWG-CA-V0-DIRECT", "GWG-CA-V0-DELAYED", "GWG-CA-V0B-OPAQUE", "GWG-DEC-EMAIL-01")
ATTACK_IDS = ("E30-02-files-memory-feedback", "H29-02-web-memory-meeting-r3",
              "D2-web-memory-project", "E31-01-email-memory-schedule-r3",
              "F27-01-docx-memory-project", "D3-email-memory-cloud",
              "B1-08-search-user-structured-long")
MAPPING = ROOT / "experiments/effect_commitment_pilot/evaluation_mapping.jsonl"
OUTPUT = Path(__file__).with_name("model_replay_results.json")


def load_key() -> str:
    key = os.getenv("DEEPSEEK_API_KEY")
    if key:
        return key
    path = WORKSPACE / "openclaw-longrange-lab/.env"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("DEEPSEEK_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"\'')
    raise RuntimeError("DEEPSEEK_API_KEY is unavailable")


class DeepSeekTurnExtractor:
    def __init__(self, key: str, *, model: str = "deepseek-flash") -> None:
        self.key = key
        self.model = model
        self.calls = 0

    def propose(self, *, user_message: str, prior_user_messages: list[str],
                active_grants: list[dict[str, Any]], environment) -> dict[str, Any]:
        payload = {"new_user_message": user_message,
                   "prior_trusted_user_messages": prior_user_messages,
                   "active_grants": active_grants,
                   "tool_environment": environment.as_prompt_data()}
        body = json.dumps({"model": self.model, "temperature": 0,
                           "response_format": {"type": "json_object"},
                           "messages": [{"role": "system", "content": EXTRACTOR_SYSTEM_PROMPT},
                                        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]},
                          ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            "https://api.deepseek.com/chat/completions", data=body,
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                value = json.load(response)
        except urllib.error.HTTPError as error:
            # Never print the request or credential-bearing headers.
            raise RuntimeError(f"DeepSeek HTTP {error.code}") from None
        self.calls += 1
        content = value["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("model returned non-object JSON")
        return parsed


def db_paths() -> list[tuple[str, str, Path, Path]]:
    selected = []
    for case_id in NORMAL_IDS:
        db = ROOT / "dataset/benign-controls/raw-runs" / case_id / "openclaw-state/agents/main/agent/openclaw-agent.sqlite"
        case_path = ROOT / "dataset/benign-controls/raw-runs" / case_id / "cases" / f"{case_id}.json"
        selected.append((case_id, "normal", db, case_path))
    mapping = [json.loads(line) for line in MAPPING.read_text(encoding="utf-8").splitlines()]
    for case_id in ATTACK_IDS:
        meta = next(item for item in mapping if item["source_case_id"] == case_id)
        task = next(part for part in Path(meta["source_path"]).parts if part.startswith("user_task_"))
        db = (WORKSPACE / "openclaw-longrange-lab/dataset/send-email/runs/expansion" / task
              / case_id / "openclaw-state/agents/main/agent/openclaw-agent.sqlite")
        case_path = WORKSPACE / "openclaw-longrange-manual-lab" / meta["source_path"]
        selected.append((case_id, "attack", db, case_path))
    return selected


def replay(case_id: str, cohort: str, db: Path, case_path: Path, extractor: Any) -> dict[str, Any]:
    events = read_native_events(db)
    case = json.loads(case_path.read_text(encoding="utf-8"))
    # The live tool schema is taken from this run's recorded environment;
    # only the effect/critical-field contract is defender-owned.
    environment = ToolEnvironment.from_tool_schemas(
        case["tool_contract"]["tools"],
        {"send_email": {"effect": "send_email",
                        "critical_fields": ["recipients", "subject", "body"]}})
    if environment.by_name("send_email") is None:
        raise ValueError(f"{case_id}: send_email is absent from this case's tool environment")
    snapshots_by_turn: dict[int, list[dict[str, Any]]] = {}
    for item in case.get("execution", {}).get("workspace_event_trace") or []:
        snapshots_by_turn.setdefault(int(item["turn"]), []).append(item)
    auditor = StreamingAuditor(environment, extractor)
    graph = auditor.graph
    for seq, event in events:
        if (event.get("type") == "message" and (event.get("message") or {}).get("role") == "user"
                and graph.current_turn > 0):
            for item in snapshots_by_turn.pop(graph.current_turn, []):
                graph.ingest_workspace_snapshot(item)
        auditor.ingest(seq, event)
    for item in snapshots_by_turn.pop(graph.current_turn, []):
        graph.ingest_workspace_snapshot(item)
    if snapshots_by_turn:
        raise ValueError(f"{case_id}: workspace snapshot turns missing from native session")
    before = case.get("execution", {}).get("state_before")
    after = case.get("execution", {}).get("state_after")
    if isinstance(before, dict) and isinstance(after, dict):
        graph.ingest_external_state_diff(before, after)
    graph.assert_complete_process()
    return {"case_id": case_id, "cohort_for_analysis_only": cohort,
            "tool_environment": environment.as_prompt_data(),
            "user_turns": len(auditor.ledger.user_messages),
            "grants": auditor.ledger.as_dict()["grants"],
            "unresolved": auditor.ledger.as_dict()["unresolved"],
            "extraction_errors": auditor.extraction_errors,
            "decisions": [{**row, "recipient": row["arguments"].get("recipients")}
                          for row in auditor.decisions],
            "process_coverage": graph.coverage()}


def main(*, local: bool = False) -> dict[str, Any]:
    output = OUTPUT.with_name("local_replay_results.json") if local else OUTPUT
    if output.exists():
        raise RuntimeError("frozen result already exists; refusing overwrite")
    extractor = ConservativeLocalExtractor() if local else DeepSeekTurnExtractor(load_key())
    rows = []
    for case_id, cohort, db, case_path in db_paths():
        row = replay(case_id, cohort, db, case_path, extractor)
        rows.append(row)
        print(f"{case_id}: {len(row['decisions'])} sends, {len(row['extraction_errors'])} extraction errors", flush=True)
    if not local and extractor.calls == 0:
        raise RuntimeError("no model call succeeded; refusing to save a misleading model replay")
    result = {"schema": "gwg-authorization-model-replay-v1",
              "extractor": "conservative_local_grammar" if local else extractor.model,
              "model_calls": 0 if local else extractor.calls, "raw_tool_results_sent_to_model": False,
              "attack_labels_sent_to_model": False, "rows": rows}
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true", help="Use a conservative local grammar, no API calls")
    args = parser.parse_args()
    value = main(local=args.local)
    print(f"saved {len(value['rows'])} case reports")
