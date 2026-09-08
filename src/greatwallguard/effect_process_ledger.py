"""A bounded process projection for persistent Effects.

``effect_ledger`` answers *what is currently left behind*.  This module adds
the complementary answer *which call produced it and what evidence supports
that link*.  It is a projection of the frozen O/A/E/S graph, not a new node
type and not a causal claim beyond the evidence on the graph edges.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .graph import digest


SCHEMA = "gwg-effect-process-ledger-v1"


def _split_record(record: dict[str, Any]) -> dict[str, Any]:
    if "graph" in record and "nodes" not in record:
        return record["graph"]
    return record


def _node_type(node: dict[str, Any]) -> str:
    value = node.get("node_type", node.get("type", ""))
    return getattr(value, "value", value)


def _edge_type(edge: dict[str, Any]) -> str:
    value = edge.get("edge_type", edge.get("relation", ""))
    return getattr(value, "value", value)


def _source_integrities(nodes: dict[str, dict[str, Any]], source_ids: list[str]) -> list[str]:
    return sorted({
        str((nodes[source_id].get("data") or {}).get("integrity", "unknown"))
        for source_id in source_ids
        if source_id in nodes and _node_type(nodes[source_id]) == "observation"
    })


def build_effect_process_ledger(
    record: dict[str, Any], *, max_entries: int | None = None,
) -> dict[str, Any]:
    """Build a deterministic process ledger from a graph or trace envelope.

    Each row is one persistent Effect, including failed Effects and Effects
    that have no committed State.  This is intentional: a failed destructive
    attempt is still useful to a detector, while ``effect_ledger`` only keeps
    committed live states.  ``max_entries`` bounds rows after newest-first
    ordering; omitted rows are represented by counts and a digest.
    """
    if max_entries is not None and max_entries < 0:
        raise ValueError("max_entries must be non-negative")

    graph = _split_record(record)
    raw_nodes = graph.get("nodes", []) or []
    nodes = {str(node.get("id")): node for node in raw_nodes if node.get("id")}
    effects = [node for node in nodes.values()
               if _node_type(node) == "effect" and (node.get("data") or {}).get("persistent", False)]

    causes: dict[str, list[dict[str, Any]]] = {}
    updates: dict[str, list[dict[str, Any]]] = {}
    derived: dict[str, list[str]] = {}
    for edge in graph.get("edges", []) or []:
        kind = _edge_type(edge)
        source, target = str(edge.get("source", "")), str(edge.get("target", ""))
        if kind == "causes":
            causes.setdefault(target, []).append(edge)
        elif kind == "updates":
            updates.setdefault(source, []).append(edge)
        elif kind == "derived_from":
            if target in nodes and _node_type(nodes[target]) == "effect":
                derived.setdefault(target, []).append(source)

    state_by_id = {str(node.get("id")): node for node in nodes.values()
                   if _node_type(node) == "state"}
    rows: list[dict[str, Any]] = []
    for effect in effects:
        effect_id = str(effect["id"])
        data = effect.get("data") or {}
        cause_edges = causes.get(effect_id, [])
        action_ids = [str(edge.get("source")) for edge in cause_edges
                      if str(edge.get("source")) in nodes and _node_type(nodes[str(edge.get("source"))]) == "action"]
        action_id = action_ids[0] if action_ids else None
        action = nodes.get(action_id, {}) if action_id else {}
        action_data = action.get("data") or {}
        source_ids = [str(value) for value in data.get("source_node_ids", []) if value]
        if not source_ids:
            source_ids = derived.get(effect_id, [])
        state_edges = updates.get(effect_id, [])
        state_ids = [str(edge.get("target")) for edge in state_edges if str(edge.get("target")) in state_by_id]
        state_id = state_ids[-1] if state_ids else None
        state = state_by_id.get(state_id, {}) if state_id else {}
        state_data = state.get("data") or {}
        status = data.get("status", "unknown")
        rows.append({
            "ledger_id": f"epl-{effect_id}",
            "effect_id": effect_id,
            "effect_turn": effect.get("turn"),
            "kind": data.get("kind", "unknown"),
            "target": data.get("target"),
            "operation": data.get("operation"),
            "status": status,
            "persistent": bool(data.get("persistent")),
            "action_id": action_id,
            "call_id": action_data.get("call_id"),
            "tool": action_data.get("tool"),
            "arguments_digest": action_data.get("arguments_digest"),
            "source_node_ids": source_ids,
            "source_integrities": _source_integrities(nodes, source_ids),
            "commit_evidence": data.get("commit_evidence"),
            "result_summary": data.get("result_summary"),
            "state_id": state_id,
            "state_version": state_data.get("version") if state_id else None,
            "state_fingerprint": state_data.get("fingerprint") if state_id else None,
            "state_evidence": state_data.get("evidence") if state_id else None,
            "state_committed": bool(state_id),
            "edge_evidence": {
                "causes": [edge.get("evidence", {}) for edge in cause_edges],
                "updates": [edge.get("evidence", {}) for edge in state_edges],
            },
        })

    rows.sort(key=lambda row: (row["effect_turn"] if row["effect_turn"] is not None else -1,
                              row["effect_id"]), reverse=True)
    omitted = rows[max_entries:] if max_entries is not None else []
    included = rows if max_entries is None else rows[:max_entries]
    return {
        "schema": SCHEMA,
        "objects": included,
        "total_effects": len(rows),
        "included_effects": len(included),
        "omitted_effects": len(omitted),
        "omitted_kinds": dict(Counter(row["kind"] for row in omitted)),
        "omitted_effect_digest": digest([row["effect_id"] for row in omitted]) if omitted else None,
        "missing_call_id": sum(row["call_id"] is None for row in rows),
    }
