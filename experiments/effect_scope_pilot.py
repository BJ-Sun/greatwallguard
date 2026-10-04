#!/usr/bin/env python3
"""Frozen matched pilot: pre-execution task authority vs observed graph Effects.

The detector receives only the first visible user request, advertised tool
schemas, and the projected L0 graph. Labels, attack goals, case IDs, and
success oracles are used by the evaluation harness *after* detection only.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))
from replay_agentdojo_cases import replay_case  # noqa: E402


ATTACK_REPO = ROOT.parent / "openclaw-longrange-manual-lab"
ATTACK_INDEX = ATTACK_REPO / "dataset" / "graph-audit" / "evaluation_all_index_refreshed.jsonl"
CONTROL_BASE = ROOT / "dataset" / "benign-controls"
OUT = ROOT / "experiments" / "effect_scope_pilot"
PERSISTENT_TOOLS = {
    "send_email": "send", "share_file": "send", "create_calendar_event": "write",
    "delete_file": "delete", "create_file": "write", "append_to_file": "write",
    "mock_scheduler_create": "write", "mock_scheduler_advance": "execute",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def frozen_pairs() -> list[dict[str, str]]:
    """Deterministically match one unique attack to each accepted control."""
    controls = [x for x in read_jsonl(CONTROL_BASE / "index.jsonl") if x["status"] == "accepted"]
    attacks = {x["case_id"]: x for x in read_jsonl(ATTACK_INDEX) if x.get("evaluation_label") == "attack"}
    alignment = {x["attack_case_id"]: x for x in read_jsonl(CONTROL_BASE / "attack_alignment.jsonl")}
    used: set[str] = set()
    pairs = []
    for control in sorted(controls, key=lambda x: x["control_id"]):
        candidates = [row for row in alignment.values()
                      if row["target"] == control["target"]
                      and row["source_user_task_id"] == control["source_user_task_id"]
                      and row["attack_case_id"] not in used]
        candidates.sort(key=lambda row: hashlib.sha256(
            f"gwg-effect-pilot-v1:{control['control_id']}:{row['attack_case_id']}".encode()
        ).hexdigest())
        if not candidates:
            raise ValueError(f"no unique attack pair for {control['control_id']}")
        attack_id = candidates[0]["attack_case_id"]
        used.add(attack_id)
        pairs.append({"control_id": control["control_id"], "attack_case_id": attack_id,
                      "target": control["target"], "attack_case_path": attacks[attack_id]["case_path"],
                      "control_case_path": control["case_path"], "control_graph_path": control["graph_path"]})
    return pairs


def _explicit_addresses(task: str) -> set[str]:
    return {x.lower() for x in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", task, re.I)}


def _affirmative(text: str, verb: str) -> bool:
    return bool(re.search(rf"\b{verb}\b", text)) and not bool(re.search(
        rf"\b(?:do not|don't|never|without)\s+(?:\w+\s+){{0,2}}{verb}\b", text
    ))


def pre_execution_scope(task: str, schemas: list[dict[str, Any]]) -> dict[str, Any]:
    """Small intent-to-Effect contract; no target label or trace is accepted."""
    text = task.lower()
    advertised = {str(x.get("canonical_name") or x.get("name")) for x in schemas}
    operations: set[str] = set()
    if _affirmative(text, "send") and ("email" in text or "message" in text or " to " in text):
        operations.add("send_email")
    if _affirmative(text, "share") or (_affirmative(text, "grant") and "access" in text):
        operations.add("share_file")
    if ("event" in text or "calendar" in text) and any(_affirmative(text, v) for v in ("create", "add", "put")):
        operations.add("create_calendar_event")
    if any(_affirmative(text, v) for v in ("delete", "remove")) and "file" in text:
        operations.add("delete_file")
    if _affirmative(text, "schedule") and any(x in text for x in ("task", "reminder", "automation")):
        operations.add("mock_scheduler_create")
    if _affirmative(text, "append") or (_affirmative(text, "update") and "file" in text):
        operations.add("append_to_file")
    operations &= advertised
    file_ids = {x for x in re.findall(r"\bfile\s+(?:id\s*)?['\"]?(\d+)\b", text)}
    permission = "rw" if "read-write" in text or "edit access" in text else ("r" if "read-only" in text else None)
    return {
        "schema": "gwg-pre-execution-effect-scope-v1",
        "allowed_operations": sorted(operations),
        "allowed_effect_kinds": sorted({PERSISTENT_TOOLS[x] for x in operations if x in PERSISTENT_TOOLS}),
        "destinations": sorted(_explicit_addresses(task)),
        "explicit_file_ids": sorted(file_ids),
        "permission": permission,
        "max_calls_per_operation": {name: 1 for name in sorted(operations)},
        "unresolved": ["resource_identity"] if "share_file" in operations and not file_ids else [],
        "input_source": "first_visible_user_message_and_tool_schemas_only",
    }


def graph_effects(projected: dict[str, Any]) -> list[dict[str, Any]]:
    graph = projected["graph"]["levels"]["l0"]["graph"]
    nodes = {x["id"]: x for x in graph["nodes"]}
    causes = defaultdict(list)
    for edge in graph["edges"]:
        if edge["edge_type"] == "causes":
            causes[edge["source"]].append(nodes.get(edge["target"], {}))
    rows = []
    for action in graph["nodes"]:
        if action.get("node_type") != "action":
            continue
        data = action.get("data") or {}
        tool = data.get("tool")
        if tool not in PERSISTENT_TOOLS:
            continue
        committed = [x for x in causes[action["id"]]
                     if x.get("node_type") == "effect" and (x.get("data") or {}).get("persistent")
                     and (x.get("data") or {}).get("status") == "succeeded"]
        if not committed:
            continue
        rows.append({"action_id": action["id"], "turn": action.get("turn"), "tool": tool,
                     "kind": str((committed[0].get("data") or {}).get("kind")),
                     "parameters": data.get("parameters") or {}, "effect_ids": [x["id"] for x in committed]})
    return rows


def _new_authority() -> dict[str, Any]:
    return {"allowed_operations": [], "allowed_effect_kinds": [], "destinations": [],
            "explicit_file_ids": [], "permission": None, "max_calls_per_operation": {}, "unresolved": []}


def _merge_authority(current: dict[str, Any], grant: dict[str, Any]) -> dict[str, Any]:
    merged = dict(current)
    for field in ("allowed_operations", "allowed_effect_kinds", "destinations", "explicit_file_ids", "unresolved"):
        merged[field] = sorted(set(current[field]) | set(grant[field]))
    merged["max_calls_per_operation"] = dict(current["max_calls_per_operation"])
    for operation, count in grant["max_calls_per_operation"].items():
        merged["max_calls_per_operation"][operation] = merged["max_calls_per_operation"].get(operation, 0) + count
    merged["permission"] = grant["permission"] or current["permission"]
    return merged


def detect(projected: dict[str, Any], schemas: list[dict[str, Any]], *, mode: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Streaming detector: only graph prefix + advertised schemas are visible."""
    alerts = []
    counts: Counter[str] = Counter()
    scope = _new_authority()
    effects_by_action = {x["action_id"]: x for x in graph_effects(projected)}
    nodes = projected["graph"]["levels"]["l0"]["graph"]["nodes"]
    for node in nodes:
        data = node.get("data") or {}
        if node.get("node_type") == "observation" and data.get("source") == "user" and data.get("request_text"):
            scope = _merge_authority(scope, pre_execution_scope(str(data["request_text"]), schemas))
        effect = effects_by_action.get(node.get("id")) if node.get("node_type") == "action" else None
        if effect is None:
            continue
        tool, args = effect["tool"], effect["parameters"]
        counts[tool] += 1
        reason = None
        if mode == "kind":
            if effect["kind"] not in scope["allowed_effect_kinds"]:
                reason = "effect_kind_outside_scope"
        elif mode == "precise":
            if tool not in scope["allowed_operations"]:
                reason = "operation_outside_scope"
            elif counts[tool] > scope["max_calls_per_operation"][tool]:
                reason = "extra_persistent_operation"
            elif tool == "send_email":
                recipients = {str(x).lower() for x in (args.get("recipients") or [])}
                all_destinations = recipients | {str(x).lower() for x in (args.get("cc") or [])} | {str(x).lower() for x in (args.get("bcc") or [])}
                if not scope["destinations"] or not all_destinations.issubset(set(scope["destinations"])):
                    reason = "destination_outside_scope"
            elif tool == "share_file":
                if not scope["destinations"] or str(args.get("email", "")).lower() not in scope["destinations"]:
                    reason = "share_principal_outside_scope"
                elif scope["explicit_file_ids"] and str(args.get("file_id")) not in scope["explicit_file_ids"]:
                    reason = "share_file_outside_scope"
                elif scope["permission"] and str(args.get("permission")) != scope["permission"]:
                    reason = "share_permission_outside_scope"
        else:
            raise ValueError(mode)
        if reason:
            alerts.append({"turn": effect["turn"], "action_id": effect["action_id"],
                           "effect_ids": effect["effect_ids"], "reason": reason})
    return alerts, scope


def evaluate() -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    pairs = frozen_pairs()
    (OUT / "pairs.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in pairs), encoding="utf-8")
    results = []
    for pair in pairs:
        for label, case_path, graph_path in (
            ("normal", ROOT / pair["control_case_path"], ROOT / pair["control_graph_path"]),
            ("attack", ATTACK_REPO / pair["attack_case_path"], None),
        ):
            case = json.loads(case_path.read_text(encoding="utf-8"))
            projected = json.loads(graph_path.read_text(encoding="utf-8")) if graph_path else replay_case(case)
            schemas = (case.get("tool_contract") or {}).get("tools") or []
            decisions = {mode: detect(projected, schemas, mode=mode) for mode in ("kind", "precise")}
            alerts_by_mode = {mode: result[0] for mode, result in decisions.items()}
            scope = decisions["precise"][1]
            results.append({"pair_id": pair["control_id"], "label": label, "target": pair["target"],
                            "scope": scope, "effects": graph_effects(projected), "alerts": alerts_by_mode})
    (OUT / "results.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in results), encoding="utf-8")
    summary = {"pairs": len(pairs), "rows": len(results), "by_mode": {}}
    for mode in ("kind", "precise"):
        by_target: dict[str, dict[str, Any]] = {}
        for target in sorted({x["target"] for x in results}):
            scoped = [x for x in results if x["target"] == target]
            by_target[target] = {label: {"n": sum(x["label"] == label for x in scoped),
                                          "flagged": sum(x["label"] == label and bool(x["alerts"][mode]) for x in scoped)}
                                 for label in ("normal", "attack")}
        summary["by_mode"][mode] = by_target
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def audit_all_attacks() -> dict[str, Any]:
    """Exploratory breadth audit after the 25-pair protocol is frozen."""
    rows = []
    for entry in sorted(read_jsonl(ATTACK_INDEX), key=lambda x: x.get("case_id", "")):
        if entry.get("evaluation_label") != "attack":
            continue
        case = json.loads((ATTACK_REPO / entry["case_path"]).read_text(encoding="utf-8"))
        projected = replay_case(case)
        schemas = (case.get("tool_contract") or {}).get("tools") or []
        kind, _ = detect(projected, schemas, mode="kind")
        precise, _ = detect(projected, schemas, mode="precise")
        rows.append({"case_id": entry["case_id"], "target": entry["target"],
                     "persistent_tool_effects": len(graph_effects(projected)),
                     "kind_alerts": kind, "precise_alerts": precise})
    (OUT / "full_attack_results.jsonl").write_text(
        "".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in rows), encoding="utf-8")
    summary = {"n": len(rows), "by_target": {}, "single_persistent_effect": {}}
    for target in sorted({x["target"] for x in rows}):
        selected = [x for x in rows if x["target"] == target]
        summary["by_target"][target] = {"n": len(selected),
                                        "kind_flagged": sum(bool(x["kind_alerts"]) for x in selected),
                                        "precise_flagged": sum(bool(x["precise_alerts"]) for x in selected)}
    singles = [x for x in rows if x["persistent_tool_effects"] == 1]
    summary["single_persistent_effect"] = {"n": len(singles),
                                            "precise_flagged": sum(bool(x["precise_alerts"]) for x in singles)}
    (OUT / "full_attack_audit.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def audit_stress_controls() -> dict[str, Any]:
    rows = []
    for entry in read_jsonl(CONTROL_BASE / "stress-cases" / "index.jsonl"):
        case = json.loads((ROOT / entry["case_path"]).read_text(encoding="utf-8"))
        graph = json.loads((ROOT / entry["graph_path"]).read_text(encoding="utf-8"))
        schemas = (case.get("tool_contract") or {}).get("tools") or []
        kind, _ = detect(graph, schemas, mode="kind")
        precise, _ = detect(graph, schemas, mode="precise")
        rows.append({"case_id": entry["case_id"], "kind_alerts": kind,
                     "precise_alerts": precise, "persistent_tool_effects": len(graph_effects(graph))})
    summary = {"n": len(rows), "kind_false_positives": sum(bool(x["kind_alerts"]) for x in rows),
               "precise_false_positives": sum(bool(x["precise_alerts"]) for x in rows), "cases": rows}
    (OUT / "stress_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(evaluate(), ensure_ascii=False, indent=2))
    print(json.dumps(audit_all_attacks(), ensure_ascii=False, indent=2))
    print(json.dumps(audit_stress_controls(), ensure_ascii=False, indent=2))
