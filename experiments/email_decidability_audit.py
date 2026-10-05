#!/usr/bin/env python3
"""Forensic audit of pre-send evidence and graph links on frozen email cases.

This does not classify an email as malicious. Labels are used only to form
descriptive cohorts; the reported evidence fields use trace prefixes and the
existing graph's non-temporal edges, never future results.
"""

from __future__ import annotations

import argparse
import json

from effect_scope_pilot import ATTACK_REPO, ROOT, read_jsonl, replay_case
from evaluate_online_effect_guard import replay as replay_online_guard
from online_effect_guard import OnlineEffectGuard


MAPPING = ROOT / "experiments" / "effect_commitment_pilot" / "evaluation_mapping.jsonl"
STRESS = ROOT / "dataset" / "benign-controls" / "stress-cases" / "GWG-STRESS-EMAIL-2" / "case.json"
LOCAL_CONTROL_ROOT = ROOT / "dataset" / "benign-controls" / "raw-runs"
CAUSAL_EDGES = {"derived_from", "reads", "causes", "updates"}


def _value(value: object) -> str:
    return str(getattr(value, "value", value)).split(".")[-1].lower()


def _ancestors(action_id: str, edges: list[dict]) -> set[str]:
    incoming: dict[str, list[str]] = {}
    for edge in edges:
        if _value(edge["edge_type"]) in CAUSAL_EDGES:
            incoming.setdefault(edge["target"], []).append(edge["source"])
    seen: set[str] = set()
    stack = list(incoming.get(action_id, []))
    while stack:
        node_id = stack.pop()
        if node_id not in seen:
            seen.add(node_id)
            stack.extend(incoming.get(node_id, []))
    return seen


def audit_case(case: dict, cohort: str) -> list[dict]:
    graph = replay_case(case)["graph"]["levels"]["l0"]["graph"]
    nodes = graph["nodes"]
    edges = graph["edges"]
    send_actions = [node for node in nodes if _value(node.get("node_type")) == "action"
                    and (node.get("data") or {}).get("tool") == "send_email"]
    sends = [row for row in sorted(case.get("execution", {}).get("tool_call_trace", []),
                                   key=lambda row: (int(row.get("turn") or 0), int(row.get("order") or 0)))
             if row.get("tool") == "send_email"]
    if len(send_actions) != len(sends):
        raise ValueError("graph/trace send count mismatch")
    user_turns = case.get("execution", {}).get("visible_agent_turns", [])
    trace = case.get("execution", {}).get("tool_call_trace", [])
    results = []
    for ordinal, (action, call) in enumerate(zip(send_actions, sends), 1):
        target = ",".join(str(x).lower() for x in ((call.get("arguments") or {}).get("recipients") or []))
        turn = int(call["turn"])
        order = int(call.get("order") or 0)
        prior_user_text = "\n".join(str(row.get("user_message") or "") for row in user_turns
                                    if int(row["turn"]) <= turn).lower()
        prior_tool_results = "\n".join(str(row.get("result") or "") for row in trace
                                       if int(row.get("turn") or 0) < turn
                                       or (int(row.get("turn") or 0) == turn and int(row.get("order") or 0) < order)).lower()
        ancestors = _ancestors(action["id"], edges)
        source_nodes = [node for node in nodes if node["id"] in ancestors and _value(node.get("node_type")) == "observation"]
        prior_nonuser = [node for node in nodes[:nodes.index(action)]
                         if _value(node.get("node_type")) == "observation"
                         and (node.get("data") or {}).get("source") != "user"]
        results.append({"cohort": cohort, "send_ordinal": ordinal, "turn": turn,
                        "destination_in_prior_user_messages": bool(target and target in prior_user_text),
                        "destination_in_prior_tool_results": bool(target and target in prior_tool_results),
                        "prior_nonuser_observations": len(prior_nonuser),
                        "linked_nonuser_observations": sum((node.get("data") or {}).get("source") != "user" for node in source_nodes),
                        "parameter_source_fields": [key for key in (action.get("data") or {})
                                                    if "provenance" in key or "source" in key]})
    return results


def run() -> dict:
    rows = []
    for meta in read_jsonl(MAPPING):
        if "send-email/" not in meta["source_path"] and "data_exfiltration_email/" not in meta["source_path"]:
            continue
        repo = ROOT if meta["source_repository"] == "greatwallguard" else ATTACK_REPO
        case = json.loads((repo / meta["source_path"]).read_text(encoding="utf-8"))
        rows.extend(audit_case(case, meta["label"]))
    rows.extend(audit_case(json.loads(STRESS.read_text(encoding="utf-8")), "normal_stress"))
    summary = {"scope": "frozen_7_attack_7_matched_normal_1_stress_email_cases",
               "groups": {}, "not_a_security_classifier": True}
    for cohort in sorted({row["cohort"] for row in rows}):
        selected = [row for row in rows if row["cohort"] == cohort]
        summary["groups"][cohort] = {
            "send_calls": len(selected),
            "send_calls_with_destination_in_user_text": sum(row["destination_in_prior_user_messages"] for row in selected),
            "send_calls_with_destination_in_prior_tool_result": sum(row["destination_in_prior_tool_results"] for row in selected),
            "send_calls_with_prior_nonuser_observation": sum(row["prior_nonuser_observations"] > 0 for row in selected),
            "send_calls_with_causal_nonuser_link": sum(row["linked_nonuser_observations"] > 0 for row in selected),
            "send_calls_with_parameter_source_field": sum(bool(row["parameter_source_fields"]) for row in selected),
        }
    summary["attack_second_send"] = {
        "calls": sum(row["cohort"] == "attack" and row["send_ordinal"] == 2 for row in rows),
        "destination_in_user_text": sum(row["cohort"] == "attack" and row["send_ordinal"] == 2
                                        and row["destination_in_prior_user_messages"] for row in rows),
        "destination_in_prior_tool_result": sum(row["cohort"] == "attack" and row["send_ordinal"] == 2
                                                and row["destination_in_prior_tool_results"] for row in rows),
        "causal_nonuser_link": sum(row["cohort"] == "attack" and row["send_ordinal"] == 2
                                   and row["linked_nonuser_observations"] > 0 for row in rows),
    }
    return summary


def audit_local_controls() -> dict:
    """Descriptive assessment of the three approved, locally retained runs."""
    results = {}
    for case_id in ("GWG-DEC-EMAIL-01", "GWG-DEC-EMAIL-02", "GWG-DEC-EMAIL-03"):
        path = LOCAL_CONTROL_ROOT / case_id / "cases" / f"{case_id}.json"
        if not path.exists():
            results[case_id] = {"available": False}
            continue
        case = json.loads(path.read_text(encoding="utf-8"))
        generation = case.get("generation") or {}
        sends = [call for call in case.get("execution", {}).get("tool_call_trace", [])
                 if call.get("tool") == "send_email" and not call.get("error")]
        result = {"available": True, "visible_turns": len(case.get("execution", {}).get("visible_agent_turns") or []),
                  "no_injection_inputs": not any(generation.get(key) for key in ("injections", "input_events", "workspace_events")),
                  "successful_send_calls": len(sends),
                  "runner_task_success": bool(case.get("run", {}).get("task_success")),
                  "runner_uses_fixed_body_oracle": True}
        if sends:
            actual = sends[0]
            result["online_baseline"] = [row for row in replay_online_guard(case) if row["tool"] == "send_email"]
            result["graph_evidence"] = audit_case(case, "local_normal_candidate")[0]
            if case_id == "GWG-DEC-EMAIL-01":
                # Analyst-supplied authorization from the visible two-turn
                # request. This is an oracle ablation, not automatic parsing.
                oracle = OnlineEffectGuard()
                oracle.commitments.append({"turn": 2, "operation": "send_email",
                                           "destination": "owner@example.com", "subject": "Project follow-up",
                                           "evidence_span": "analyst_request_only_oracle"})
                decision = oracle.before_tool_call("send_email", actual.get("arguments") or {},
                                                   turn=int(actual["turn"]), call_id="oracle-send")
                result["analyst_scope_oracle_verdict"] = decision.verdict
                result["analyst_scope_oracle_reason"] = decision.reason
        results[case_id] = result
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-local-controls", action="store_true")
    args = parser.parse_args()
    output = run()
    if args.include_local_controls:
        output["local_controls"] = audit_local_controls()
    print(json.dumps(output, ensure_ascii=False, indent=2))
