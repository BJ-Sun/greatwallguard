"""Replay AgentDojo case JSON into the existing GreatWallGuard graph.

This is intentionally an offline adapter: it does not call a model or rerun a
tool.  The case JSON remains the source of truth and the L0-L3 graph is a
derived comparison artifact.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from greatwallguard import (
    EffectType,
    GreatWallGuardRuntime,
    TaskScope,
    ToolContractRegistry,
    build_multi_level_graph,
)
from greatwallguard.contracts import ToolContract
from greatwallguard.model import Effect


def _first(args: dict[str, Any]) -> str:
    for key in ("path", "filename", "file_id", "file", "url", "query", "channel", "user", "hotel", "recipient", "recipients"):
        if key in args and args[key] is not None:
            return str(args[key])
    return "unknown"


def _effect_for_tool(tool: str, args: dict[str, Any]) -> Effect:
    """Use a generic verb classifier, not a per-tool graph schema."""
    normalized = tool.lower()
    verb = tool.split("_", 1)[0].lower()
    target = f"tool://{tool}/{_first(args)}"
    if "scheduler" in normalized and any(token in normalized for token in ("create", "update", "delete", "remove")):
        return Effect(EffectType.WRITE, target, "scheduler_create", persistent=True)
    if "scheduler" in normalized and any(token in normalized for token in ("advance", "trigger", "run")):
        return Effect(EffectType.EXECUTE, target, "scheduler_execute", persistent=True, reversible=False)
    if verb in {"get", "search", "list", "read", "check", "fetch", "find", "query", "look"}:
        return Effect(EffectType.READ, target, tool, persistent=False)
    if verb in {"delete", "remove", "cancel"}:
        return Effect(EffectType.DELETE, target, tool, persistent=True, reversible=False)
    if verb in {"send", "share", "invite", "post"}:
        return Effect(EffectType.SEND, target, tool, persistent=True, reversible=False)
    if verb in {"create", "add", "append", "update", "schedule", "reserve", "set"}:
        return Effect(EffectType.WRITE, target, tool, persistent=True)
    if verb in {"exec", "run"}:
        return Effect(EffectType.EXECUTE, target, tool, persistent=True, reversible=False)
    return Effect(EffectType.UNKNOWN, target, tool, persistent=True, reversible=False)


def _registry_for_tools(tools: set[str]) -> ToolContractRegistry:
    registry = ToolContractRegistry()
    for tool in tools:
        registry.register(ToolContract(tool, lambda args, _tool=tool: [_effect_for_tool(_tool, args)]))
    return registry


def replay_case(case: dict[str, Any]) -> dict[str, Any]:
    spec = case
    execution = case.get("execution") or case.get("run") or {}
    trace = execution.get("tool_call_trace") or []
    tools = {str(item.get("tool", "")) for item in trace if item.get("tool")}
    scope = TaskScope(
        task_id=str(case.get("case_id", "unknown")),
        intent=str(case.get("benign_task", "")),
        allowed_effects=frozenset(EffectType),
        allowed_destinations=("",),
    )
    runtime = GreatWallGuardRuntime(scope, contracts=_registry_for_tools(tools))
    previous = runtime.observe_user(str(case.get("benign_task", "")))
    execution = case.get("execution") or {}
    workspace_changes = execution.get("workspace_event_trace") or []
    workspace_reads = execution.get("workspace_read_trace") or []
    handled_workspace_turns: set[int] = set()

    def replay_workspace_turn(turn: int) -> None:
        nonlocal previous
        if turn in handled_workspace_turns:
            return
        handled_workspace_turns.add(turn)
        for event in workspace_changes:
            if int(event.get("turn", 0)) == turn:
                previous = runtime.record_workspace_change(
                    event,
                    call_id=f"{case.get('case_id', 'case')}-workspace-{turn}-{event.get('path')}",
                )
        for event in workspace_reads:
            if int(event.get("turn", 0)) == turn:
                previous = runtime.observe_workspace_read(
                    path=str(event.get("path", "")),
                    fingerprint=event.get("sha256"),
                    turn=turn,
                    evidence_level=str(event.get("evidence_level", "observed")),
                    evidence_method=str(event.get("evidence_method", "workspace_runtime")),
                    version=event.get("version_hint"),
                )

    trace_by_turn: dict[int, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for index, item in enumerate(trace, start=1):
        trace_by_turn[int(item.get("turn", index))].append((index, item))
    all_turns = set(trace_by_turn)
    all_turns.update(int(event.get("turn", 0)) for event in workspace_changes + workspace_reads)
    for current_turn in sorted(turn for turn in all_turns if turn > 0):
        for index, item in trace_by_turn.get(current_turn, []):
            tool = str(item.get("tool", "unknown"))
            arguments = item.get("arguments") or item.get("args") or {}
            try:
                runtime.before_tool_call(
                    tool,
                    arguments,
                    source_node_ids=(previous,),
                    turn=current_turn,
                    call_id=str(item.get("call_id") or f"{case.get('case_id', 'case')}-{index}"),
                    execute=lambda item=item: _execute_recorded(item),
                )
            except RuntimeError:
                # The runtime records failed Effects and deliberately re-raises;
                # continue replay so later events remain auditable.
                pass
            previous = runtime.observe(
                "tool_return",
                str(item.get("result", "")),
                integrity="unknown",
                turn=current_turn,
                object_id=f"tool://{tool}",
                raw_payload={"result": item.get("result"), "injected": bool(item.get("injected", False))},
            )
        replay_workspace_turn(current_turn)
    trace_record = runtime.trace_dict()
    levels = build_multi_level_graph(trace_record)
    run = case.get("run") or {}
    return {
        "case_id": case.get("case_id"),
        "seed_suite": case.get("seed_suite"),
        "attack_variant": case.get("attack_variant"),
        "victim_model": (case.get("transfer") or {}).get("source_victim_model") or run.get("victim_model"),
        "label": case.get("label"),
        "task_success": run.get("task_success", run.get("utility_ok")),
        "attack_success": run.get("attack_success", run.get("success")),
        "outcome_cell": run.get("outcome_cell"),
        "first_harm_turn": run.get("first_harm_turn"),
        "graph": levels,
        "graph_meta": levels.get("meta", {}),
    }


def _execute_recorded(item: dict[str, Any]) -> Any:
    if item.get("error") or str(item.get("result", "")).startswith(("Error:", "Tool execution failed")):
        raise RuntimeError(str(item.get("error") or item.get("result")))
    return item.get("result", "")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in sorted(Path(args.cases_dir).glob("*.json")):
        with path.open(encoding="utf-8") as fh:
            rows.append(replay_case(json.load(fh)))
    for row in rows:
        with (output / f"{row['case_id']}.json").open("w", encoding="utf-8") as fh:
            json.dump(row, fh, ensure_ascii=False, indent=2, default=str)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[f"{row.get('seed_suite')}::{row.get('attack_variant')}"] .append(row)
    comparison = {
        "case_count": len(rows),
        "groups": {
            key: {
                "case_count": len(items),
                "attack_successes": sum(bool(item.get("attack_success")) for item in items),
                "task_successes": sum(item.get("task_success") is True for item in items),
                "mean_l0_nodes": sum(item["graph_meta"]["bytes"].get("l0", 0) for item in items) / len(items),
                "mean_l3_alerts": sum(item["graph_meta"].get("l3_alerts", 0) for item in items) / len(items),
                "mean_l2_effects": sum(item["graph_meta"].get("l2_process_effects", 0) for item in items) / len(items),
            }
            for key, items in sorted(grouped.items())
        },
    }
    with (output / "comparison.json").open("w", encoding="utf-8") as fh:
        json.dump(comparison, fh, ensure_ascii=False, indent=2)
    print(json.dumps(comparison, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
