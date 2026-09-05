"""Small, model-independent metrics for normal-task graph validation."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .model import EdgeType, NodeType
from .trace import TraceEventType


def summarize_runtime(runtime, *, raw_payload_chars: int = 0) -> dict[str, Any]:
    graph = runtime.graph
    node_counts = Counter(node.node_type.value for node in graph.nodes.values())
    edge_counts = Counter(edge.edge_type.value for edge in graph.edges)
    event_counts = Counter(event.event_type.value for event in runtime.trace.events)
    effect_nodes = [node for node in graph.nodes.values() if node.node_type is NodeType.EFFECT]
    committed_effects = sum(node.data.get("status") == "succeeded" for node in effect_nodes)
    graph_bytes = len(json.dumps(runtime.trace_dict(), ensure_ascii=False, default=str).encode("utf-8"))
    compact_bytes = len(json.dumps(runtime.compact_context(), ensure_ascii=False, default=str).encode("utf-8"))
    return {
        "turns": runtime.turn,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "node_counts": dict(node_counts),
        "edge_counts": dict(edge_counts),
        "trace_event_counts": dict(event_counts),
        "persistent_effects": sum(bool(node.data.get("persistent")) for node in effect_nodes),
        "committed_effects": committed_effects,
        "state_versions": len(graph.state_versions),
        "state_read_edges": edge_counts.get(EdgeType.READS.value, 0),
        "action_capture_rate": event_counts.get(TraceEventType.ACTION_PROPOSED.value, 0)
        / max(node_counts.get(NodeType.ACTION.value, 0), 1),
        "effect_commit_rate": committed_effects / max(len(effect_nodes), 1),
        "raw_payload_chars": raw_payload_chars,
        "graph_bytes": graph_bytes,
        "graph_to_raw_ratio": graph_bytes / max(raw_payload_chars, 1),
        "compact_bytes": compact_bytes,
        "compact_to_raw_ratio": compact_bytes / max(raw_payload_chars, 1),
    }
