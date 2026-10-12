#!/usr/bin/env python3
"""Descriptive, label-separated audit of frozen email graphs.

Only base L1 graph nodes/edges are used. No case target, injection plan,
semantic overlay, prior detection verdict, or tool trace enters feature
extraction. Cohort names are attached only after per-graph extraction.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
ATTACK_ROOT = WORKSPACE / "openclaw-longrange-manual-lab/dataset/send-email/curated/double-success"
NORMAL_ROOT = WORKSPACE / "greatwallguard/dataset/benign-controls/cases/data_exfiltration_email"
STRESS_GRAPH = WORKSPACE / "greatwallguard/dataset/benign-controls/stress-cases/GWG-STRESS-EMAIL-2/graph.json"
LOCAL_NORMAL_RUNS = WORKSPACE / "greatwallguard/dataset/benign-controls/raw-runs"
FAILED_CATALOG = WORKSPACE / "openclaw-longrange-manual-lab/dataset/send-email/catalog/by-outcome/failed.jsonl"
FAILED_RUNS = WORKSPACE / "openclaw-longrange-lab/dataset/send-email/runs"


def extract(path: Path, *, reproject: bool) -> dict:
    if reproject:
        repo = WORKSPACE / "greatwallguard"
        sys.path.insert(0, str(repo / "src"))
        sys.path.insert(0, str(repo))
        from experiments.replay_agentdojo_cases import replay_case

        case_path = path if path.name != "graph.json" else path.parent / "case.json"
        case = json.loads(case_path.read_text(encoding="utf-8"))
        document = replay_case(case)
    else:
        document = json.loads(path.read_text(encoding="utf-8"))
    levels = document["graph"]["levels"]
    graph = levels["l1"]
    state_graph = levels["l2"]
    nodes = graph["nodes"]
    edges = graph["edges"]
    by_id = {node["id"]: node for node in nodes}
    producer_by_effect: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        if edge.get("relation") == "causes":
            producer_by_effect[edge["target"]].append(edge["source"])

    user_nodes = [node for node in nodes if node.get("node_type") == "observation"
                  and (node.get("data") or {}).get("source") == "user"]
    actions = [node for node in nodes if node.get("node_type") == "action"]
    effects = [node for node in nodes if node.get("node_type") == "effect"]
    sends = []
    for effect in effects:
        data = effect.get("data") or {}
        if data.get("operation") != "send" or data.get("status") != "succeeded":
            continue
        source_ids = data.get("source_node_ids") or []
        source_descriptions = []
        nonproducer_action_source = False
        for source_id in source_ids:
            source = by_id.get(source_id) or {}
            source_data = source.get("data") or {}
            source_descriptions.append({
                "node_type": source.get("node_type", "missing"),
                "source": source_data.get("source"),
                "tool": source_data.get("tool"),
            })
            if source.get("node_type") == "action" and source_id not in producer_by_effect[effect["id"]]:
                nonproducer_action_source = True
        sends.append({
            "turn": effect.get("turn"),
            "targets": [target.get("value") for target in data.get("targets") or []],
            "source_descriptions": source_descriptions,
            "source_is_unrelated_action": nonproducer_action_source,
            "commit_basis": (data.get("commit_evidence") or {}).get("basis"),
            "field_effects_present": bool(data.get("field_effects")),
        })

    persistent = [node for node in effects if (node.get("data") or {}).get("persistent")
                  and (node.get("data") or {}).get("status") == "succeeded"]
    workspace_mutations = [node for node in persistent if any(
        str(target.get("value", "")).startswith("workspace://")
        for target in (node.get("data") or {}).get("targets") or []
    )]
    derived_edges = [edge for edge in edges if edge.get("relation") == "derived_from"]
    ledger_sends = [item for item in (state_graph.get("process_ledger") or {}).get("objects") or []
                    if item.get("kind") == "send" and item.get("status") == "succeeded"]
    send_activations = [item for item in state_graph.get("activations") or [] if item.get("operation") == "send"]
    return {
        "case_id": document.get("case_id"),
        "source_path": str(path.relative_to(WORKSPACE)),
        "l1_nodes": len(nodes),
        "action_count": len(actions),
        "user_observation_count": len(user_nodes),
        "user_observation_with_text": sum(bool((node.get("data") or {}).get("request_text")) for node in user_nodes),
        "actions_with_parameters": sum("parameters" in (node.get("data") or {}) for node in actions),
        "send_count": len(sends),
        "sends": sends,
        "persistent_workspace_mutations": Counter((node.get("data") or {}).get("operation") for node in workspace_mutations),
        "derived_edges": len(derived_edges),
        "derived_edges_unspecified": sum((edge.get("evidence") or {}).get("basis") == "unspecified"
                                         for edge in derived_edges),
        "l2_send_ledger_with_parameters": sum(item.get("parameters") is not None for item in ledger_sends),
        "l2_send_activations": len(send_activations),
        "l2_send_activations_with_unspecified_edge": sum(
            any(evidence.get("basis") == "unspecified" for evidence in item.get("evidence_chain") or [])
            for item in send_activations
        ),
    }


def summarize(rows: list[dict]) -> dict:
    result = {}
    for cohort in ("attack_double_success", "attack_failed_task_success", "attack_failed_task_failure",
                   "normal_clean", "normal_two_send_stress", "normal_conditional_verified",
                   "normal_multiturn_exploratory"):
        subset = [row for row in rows if row["cohort"] == cohort]
        result[cohort] = {
            "cases": len(subset),
            "send_count_distribution": dict(sorted(Counter(row["send_count"] for row in subset).items())),
            "send_target_sequences": [
                {"targets": list(targets), "cases": count}
                for targets, count in Counter(
                    tuple(target for send in row["sends"] for target in send["targets"])
                    for row in subset
                ).most_common()
            ],
            "graphs_without_user_text": sum(row["user_observation_with_text"] == 0 for row in subset),
            "graphs_without_action_parameters": sum(row["actions_with_parameters"] == 0 for row in subset),
            "send_effects": sum(row["send_count"] for row in subset),
            "send_effects_with_nonproducer_action_source": sum(
                send["source_is_unrelated_action"] for row in subset for send in row["sends"]
            ),
            "send_effects_with_field_effects": sum(
                send["field_effects_present"] for row in subset for send in row["sends"]
            ),
            "workspace_mutation_distribution": dict(sorted(Counter(
                sum(row["persistent_workspace_mutations"].values()) for row in subset
            ).items())),
            "derived_edges": sum(row["derived_edges"] for row in subset),
            "derived_edges_unspecified": sum(row["derived_edges_unspecified"] for row in subset),
            "l2_send_ledger_with_parameters": sum(row["l2_send_ledger_with_parameters"] for row in subset),
            "l2_send_activations": sum(row["l2_send_activations"] for row in subset),
            "l2_send_activations_with_unspecified_edge": sum(
                row["l2_send_activations_with_unspecified_edge"] for row in subset
            ),
        }
    return result


def main() -> None:
    reproject = "--reproject" in sys.argv[1:]
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and not reproject):
        raise SystemExit("usage: audit.py [--reproject]")
    groups = {
        "attack_double_success": sorted(ATTACK_ROOT.glob("*/*/graph.json")),
        "normal_clean": sorted(NORMAL_ROOT.glob("*/graph.json")),
        "normal_two_send_stress": [STRESS_GRAPH],
    }
    expected = {"attack_double_success": 49, "normal_clean": 7, "normal_two_send_stress": 1}
    if reproject:
        failed_rows = [json.loads(line) for line in FAILED_CATALOG.read_text(encoding="utf-8").splitlines() if line.strip()]
        for outcome, cohort in (("attack_failure__task_success", "attack_failed_task_success"),
                                ("attack_failure__task_failure", "attack_failed_task_failure")):
            groups[cohort] = sorted(FAILED_RUNS / row["case_id"] / "cases" / f"{row['case_id']}.json"
                                    for row in failed_rows if row["outcome"] == outcome)
        expected.update({"attack_failed_task_success": 9, "attack_failed_task_failure": 4})
        groups["normal_conditional_verified"] = [
            LOCAL_NORMAL_RUNS / case_id / "cases" / f"{case_id}.json"
            for case_id in ("GWG-CA-V0-DIRECT", "GWG-CA-V0-DELAYED")
        ]
        groups["normal_multiturn_exploratory"] = [
            LOCAL_NORMAL_RUNS / case_id / "cases" / f"{case_id}.json"
            for case_id in ("GWG-DEC-EMAIL-01", "GWG-DEC-EMAIL-02", "GWG-DEC-EMAIL-03")
        ]
        expected.update({"normal_conditional_verified": 2, "normal_multiturn_exploratory": 3})
    actual = {key: len(paths) for key, paths in groups.items()}
    if actual != expected:
        raise SystemExit(f"Dataset inventory changed: expected={expected}, actual={actual}")
    rows = []
    for cohort, paths in groups.items():
        for path in paths:
            row = extract(path, reproject=reproject)
            row["cohort"] = cohort
            row["persistent_workspace_mutations"] = dict(row["persistent_workspace_mutations"])
            rows.append(row)
    summary = {
        "schema": "gwg-email-graph-posthoc-v0",
        "projection": "uniform_replay_from_frozen_case" if reproject else "stored_graph_artifacts",
        "feature_source": "base L1/L2 graph only; labels added after extraction",
        "excluded_from_comparison": ["case.target_effect", "case.injection_payload_or_plan", "semantic_overlay", "detection"],
        "projection_input": "frozen case execution.tool_call_trace and visible user turns" if reproject else "stored graph",
        "cohorts": summarize(rows),
    }
    suffix = "_reprojected" if reproject else ""
    (HERE / f"case_features{suffix}.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    (HERE / f"summary{suffix}.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
