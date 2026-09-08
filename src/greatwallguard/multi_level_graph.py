"""Tool-agnostic multi-level projections of one audit trace.

The projections are deliberately loss-aware.  L0 is the saved audit graph;
L1 normalizes its fields without changing event identity; L2 groups events by
persistent object and exposes propagation/activation paths; L3 is the bounded
summary used by the first detector.  Every upper-level row keeps the L0 IDs it
was derived from so a finding can be audited against the original trace.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .effect_process_ledger import build_effect_process_ledger
from .graph import digest
from .graph_detection import detect_graph_baseline
from .state_summary import MEDIUM, GraphStateSummarizer, SummaryBudgets


SCHEMA = "gwg-multi-level-graph-v1"


def _split_record(record: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if "graph" in record and "nodes" not in record:
        return record["graph"], record.get("events", []) or []
    return record, record.get("events", []) or []


def _value(value: Any) -> Any:
    return getattr(value, "value", value)


def _type(node: dict[str, Any]) -> str:
    return str(_value(node.get("node_type", node.get("type", ""))))


def _edge_type(edge: dict[str, Any]) -> str:
    return str(_value(edge.get("edge_type", edge.get("relation", ""))))


def _content_ref(data: dict[str, Any]) -> str | None:
    content = data.get("content") or {}
    return content.get("ref") if isinstance(content, dict) else None


def _level1(graph: dict[str, Any]) -> dict[str, Any]:
    """Normalize each existing O/A/E/S node into a tool-independent record."""
    raw_nodes = graph.get("nodes", []) or []
    nodes = {str(node.get("id")): node for node in raw_nodes if node.get("id")}
    causes: dict[str, list[str]] = defaultdict(list)
    for edge in graph.get("edges", []) or []:
        if _edge_type(edge) == "causes":
            causes[str(edge.get("target"))].append(str(edge.get("source")))
    effect_by_action: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for effect_id, action_ids in causes.items():
        effect = nodes.get(effect_id)
        if not effect or _type(effect) != "effect":
            continue
        for action_id in action_ids:
            effect_by_action[action_id].append(effect)

    normalized: list[dict[str, Any]] = []
    for node in raw_nodes:
        node_id = str(node["id"])
        kind = _type(node)
        data = node.get("data") or {}
        common = {
            "id": node_id,
            "node_type": kind,
            "turn": node.get("turn"),
            "label": node.get("label"),
            "children_ids": [node_id],
        }
        if kind == "observation":
            common["data"] = {
                "source": data.get("source"),
                "integrity": data.get("integrity", "unknown"),
                "object_id": data.get("object_id"),
                "content_ref": _content_ref(data),
                "session_id": data.get("session_id"),
                "phase": data.get("phase"),
            }
        elif kind == "action":
            effects = effect_by_action.get(node_id, [])
            operations = sorted({str((effect.get("data") or {}).get("kind", "unknown"))
                                 for effect in effects})
            common["data"] = {
                "tool": data.get("tool"),
                "operation": operations[0] if len(operations) == 1 else (operations or ["unknown"]),
                "operations": operations,
                "call_id": data.get("call_id"),
                "arguments_digest": data.get("arguments_digest"),
                "decision": data.get("decision"),
                "execution_status": data.get("execution_status"),
            }
        elif kind == "effect":
            common["data"] = {
                "operation": data.get("kind", "unknown"),
                "raw_operation": data.get("operation"),
                "targets": [{"role": "target", "value": data.get("target")}],
                "persistent": bool(data.get("persistent")),
                "reversible": data.get("reversible"),
                "status": data.get("status"),
                "source_node_ids": list(data.get("source_node_ids", []) or []),
                "commit_evidence": data.get("commit_evidence"),
            }
        elif kind == "state":
            common["data"] = {
                "object_id": data.get("object_id"),
                "version": data.get("version"),
                "fingerprint": data.get("fingerprint"),
                "effect_id": data.get("effect_id"),
                "evidence": data.get("evidence") or data.get("commit_evidence"),
            }
        else:
            common["data"] = dict(data)
        normalized.append(common)

    edges = [{
        "source": edge.get("source"),
        "target": edge.get("target"),
        "relation": _edge_type(edge),
        "turn": edge.get("turn"),
        "evidence": edge.get("evidence", {}),
    } for edge in graph.get("edges", []) or []]
    return {
        "schema": "gwg-process-graph-v1",
        "nodes": normalized,
        "edges": edges,
        "node_count": len(normalized),
        "edge_count": len(edges),
    }


def _level2(graph: dict[str, Any]) -> dict[str, Any]:
    """Aggregate L0 by object and expose state-read activation chains."""
    raw_nodes = graph.get("nodes", []) or []
    nodes = {str(node.get("id")): node for node in raw_nodes if node.get("id")}
    states_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in raw_nodes:
        if _type(node) != "state":
            continue
        data = node.get("data") or {}
        object_id = str(data.get("object_id", ""))
        if object_id:
            states_by_object[object_id].append(node)
    histories = []
    for object_id, states in states_by_object.items():
        states.sort(key=lambda node: (int((node.get("data") or {}).get("version", 0) or 0),
                                      node.get("turn", 0), node.get("id", "")))
        histories.append({
            "object_id": object_id,
            "state_ids": [node["id"] for node in states],
            "versions": [{
                "state_id": node["id"],
                "version": (node.get("data") or {}).get("version"),
                "turn": node.get("turn"),
                "effect_id": (node.get("data") or {}).get("effect_id"),
                "fingerprint": (node.get("data") or {}).get("fingerprint"),
            } for node in states],
            "latest_state_id": states[-1]["id"],
        })
    histories.sort(key=lambda item: item["object_id"])

    reads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    derived_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    causes_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in graph.get("edges", []) or []:
        kind = _edge_type(edge)
        target = str(edge.get("target"))
        if kind == "reads":
            reads[target].append(edge)
        elif kind == "derived_from":
            derived_by_source[str(edge.get("source"))].append(edge)
        elif kind == "causes":
            causes_by_source[str(edge.get("source"))].append(edge)

    activations = []
    for observation_id, read_edges in reads.items():
        for read_edge in read_edges:
            state_id = str(read_edge.get("source"))
            for derived_edge in derived_by_source.get(observation_id, []):
                action_id = str(derived_edge.get("target"))
                for edge in causes_by_source.get(action_id, []):
                    effect_id = str(edge.get("target"))
                    effect = nodes.get(effect_id, {})
                    effect_data = effect.get("data") or {}
                    activations.append({
                        "state_id": state_id,
                        "observation_id": observation_id,
                        "action_id": action_id,
                        "effect_id": effect_id,
                        "operation": effect_data.get("kind", "unknown"),
                        "turn": effect.get("turn"),
                        "evidence_chain": [read_edge.get("evidence", {}),
                                           derived_edge.get("evidence", {}),
                                           edge.get("evidence", {})],
                    })
    activations.sort(key=lambda item: (item.get("turn", -1), item["effect_id"]))

    session_ids = sorted({
        str((node.get("data") or {}).get("session_id"))
        for node in raw_nodes
        if (node.get("data") or {}).get("session_id") is not None
    })
    process_ledger = build_effect_process_ledger(graph)
    return {
        "schema": "gwg-state-propagation-graph-v1",
        "objects": histories,
        "process_ledger": process_ledger,
        "activations": activations,
        "session_ids": session_ids,
        "object_count": len(histories),
        "activation_count": len(activations),
    }


def build_level1_process_graph(record: dict[str, Any]) -> dict[str, Any]:
    """Build only the normalized process projection (L1)."""
    graph, _ = _split_record(record)
    return _level1(graph)


def build_level2_state_graph(record: dict[str, Any]) -> dict[str, Any]:
    """Build only the state/propagation projection (L2)."""
    graph, _ = _split_record(record)
    return _level2(graph)


def build_multi_level_graph(
    record: dict[str, Any], *, budgets: SummaryBudgets = MEDIUM,
    raw_texts: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build L0/L1/L2/L3 views from one saved trace or graph."""
    graph, events = _split_record(record)
    level1 = build_level1_process_graph(record)
    level2 = build_level2_state_graph(record)
    summary = GraphStateSummarizer(budgets=budgets).summarize(
        record, raw_texts=raw_texts or {})
    detection = detect_graph_baseline(record)
    levels = {
        "l0": {"schema": "gwg-audit-graph-v1", "graph": graph, "events": events},
        "l1": level1,
        "l2": level2,
        "l3": {"schema": "gwg-runtime-detection-graph-v1",
               "summary": summary, "detection": detection},
    }
    sizes = {
        name: len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
        for name, value in levels.items()
    }
    return {
        "schema": SCHEMA,
        "levels": levels,
        "meta": {
            "bytes": sizes,
            "compression_ratio": {
                name: size / max(sizes["l0"], 1) for name, size in sizes.items()
            },
            "l0_digest": digest(graph),
            "l1_children_are_l0_ids": True,
            "l2_process_effects": level2["process_ledger"]["total_effects"],
            "l3_alerts": detection["alert_count"],
        },
    }
