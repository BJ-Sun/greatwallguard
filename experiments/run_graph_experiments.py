"""Build comparable GreatWallGuard graphs for normal and AgentLAB runs.

The attack side is passive: AgentLAB still executes its original mock tools and
judge, while :func:`patch_agentlab` records the same run into an EffectGraph.
No real email, shell command, or external side effect is enabled.

Example (from the ``greatwallguard`` directory)::

    PYTHONPATH=src ../attack-generation/openclaw-agentlab/.venv/bin/python \
      experiments/run_graph_experiments.py --normal-turns 50 150 \
      --direct-cases LONG-001 LONG-003 --dojo-filter user_task_15+injection_task_0 \
      --max-turns 2 --max-rounds 6
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from greatwallguard import EffectType, TaskScope
from greatwallguard.agentlab_recorder import AgentLabGraphRecorder, patch_agentlab
from greatwallguard.metrics import summarize_runtime


THIS_DIR = Path(__file__).resolve().parent
GUARD_ROOT = THIS_DIR.parent
WORKSPACE_ROOT = GUARD_ROOT.parent
AGENTLAB_ROOT = WORKSPACE_ROOT / "attack-generation" / "openclaw-agentlab-upstream"
DEFAULT_ENV = WORKSPACE_ROOT / "attack-generation" / "openclaw-agentlab" / ".env"
DEFAULT_OUTPUT = GUARD_ROOT / "experiments" / "results"


def _json_default(value: Any):
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "__dict__"):
        return value.__dict__
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default), encoding="utf-8")


def _load_agentlab():
    root = str(AGENTLAB_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from src.config import ATTACK_INSTANCES
    from src.dojo_skill_bridge import DojoSkillBridge
    from src.orchestrator import Orchestrator
    return ATTACK_INSTANCES, DojoSkillBridge, Orchestrator


def _load_dojo_runner():
    path = AGENTLAB_ROOT / "scripts" / "run_dojo_benchmark.py"
    spec = importlib.util.spec_from_file_location("greatwallguard_dojo_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_env(path: Path) -> None:
    """Load the existing local attack .env without writing it elsewhere."""
    try:
        from dotenv import load_dotenv
        load_dotenv(path, override=False)
    except ImportError:
        return
    # The legacy runner insists on GEMINI_API_KEY even when LLMClient selects
    # the explicitly configured DeepSeek endpoint.
    if not os.environ.get("GEMINI_API_KEY") and os.environ.get("DEEPSEEK_API_KEY"):
        os.environ["GEMINI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
    if not os.environ.get("GEMINI_API_URL") and os.environ.get("DEEPSEEK_API_URL"):
        os.environ["GEMINI_API_URL"] = os.environ["DEEPSEEK_API_URL"]


def _scope(task_id: str, intent: str) -> TaskScope:
    return TaskScope(
        task_id=task_id,
        intent=intent,
        allowed_effects=frozenset(EffectType),
        allowed_resources=(),
        allowed_destinations=(),
    )


def run_normal(turns: int, output_root: Path) -> dict[str, Any]:
    """Run the deterministic long normal task and save all three graph views."""
    path = GUARD_ROOT / "examples" / "normal_long_task.py"
    spec = importlib.util.spec_from_file_location("greatwallguard_normal_long_task", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    guard, raw_chars = module.run(turns)
    metrics = summarize_runtime(guard, raw_payload_chars=raw_chars)
    payload = {
        "label": "normal",
        "case": f"deterministic_normal_{turns}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "compact_view": guard.compact_context(),
        "minimal_graph": guard.minimal_graph(),
        **guard.trace_dict(),
    }
    target = output_root / "normal" / f"normal_{turns:04d}.json"
    _write_json(target, payload)
    return {"label": "normal", "case": f"normal_{turns}", "path": str(target), "metrics": metrics}


def _attack_meta(attack: Any) -> dict[str, Any]:
    return {
        "id": attack.id,
        "name": attack.name,
        "attack_type": attack.attack_type,
        "risk_category": attack.risk_category,
        "dojo_suite": getattr(attack, "dojo_suite", ""),
        "benign_task": attack.benign_task,
        "malicious_goal": attack.malicious_goal,
    }


def _result_meta(result: Any) -> dict[str, Any]:
    keys = (
        "attack_id", "attack_name", "attack_type", "success", "goal_progress",
        "utility_ok", "security_breach", "total_turns", "total_tool_calls",
        "prompt_harmlessness", "stealth_ok", "success_horizon_turn",
        "long_range_eligible", "bsr", "violations", "summary",
    )
    return {key: getattr(result, key, None) for key in keys}


def _attack_instance(case_id: str):
    instances, _, _ = _load_agentlab()
    for attack in instances:
        if attack.id == case_id:
            return copy.deepcopy(attack)
    raise ValueError(f"unknown attack id {case_id}; available: {[a.id for a in instances]}")


def _dynamic_attack(task_filter: str, variant: str):
    runner = _load_dojo_runner()
    attacks = runner.generate_dojo_attacks(
        "workspace", limit=1, attack_variant=variant, task_filter=task_filter,
    )
    if not attacks:
        raise ValueError(f"no AgentDojo pair matched {task_filter}")
    return copy.deepcopy(attacks[0])


def run_attack(
    attack: Any,
    *,
    output_root: Path,
    max_turns: int,
    max_rounds: int,
    defense_types: list[str] | None = None,
) -> dict[str, Any]:
    """Run one existing case and classify it by the observed judge result."""
    _, bridge_cls, orchestrator_cls = _load_agentlab()
    # Benign counterparts are a separate utility measurement.  Excluding them
    # here keeps this graph strictly about the anomalous run being classified.
    attack.benign_counterpart_seeds = []
    recorder = AgentLabGraphRecorder(_scope(f"trace-{attack.id}", attack.benign_task))
    bridge = bridge_cls(attack.dojo_suite) if getattr(attack, "dojo_suite", "") else None
    if bridge:
        bridge.reset()
    orch = orchestrator_cls(
        victim_model=os.environ.get("VICTIM_MODEL", "deepseek-chat"),
        max_turns=max_turns,
        defense_types=defense_types or [],
        memory_bank_path=str(output_root / "memory_bank.json"),
    )
    orch.max_agent_rounds = max_rounds
    with patch_agentlab(recorder):
        result = orch.run_attack(attack, verbose=False, skill_bridge=bridge)

    label = "attack_success" if bool(result.success) else "attack_failure"
    safe_case = attack.id.lower().replace("/", "_")
    target = output_root / label / f"{safe_case}.json"
    payload = recorder.export(
        label=label,
        result={"attack": _attack_meta(attack), "outcome": _result_meta(result)},
    )
    payload["created_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(target, payload)
    return {
        "label": label,
        "case": attack.id,
        "name": attack.name,
        "path": str(target),
        "metrics": payload["metrics"],
        "outcome": _result_meta(result),
    }


def run_success_replay(case_id: str, *, output_root: Path) -> dict[str, Any]:
    """Replay an existing case's ground-truth malicious calls in the mock.

    This is intentionally marked as an oracle replay, not an LLM ASR result.
    It gives the graph experiment a deterministic ``attack_success`` specimen
    even when stochastic Planner/Agent/Judge runs fail to reach the goal.
    """
    instances, _, _ = _load_agentlab()
    attack = _attack_instance(case_id)
    from src.environment import OpenClawEnvironment
    from src.workspace import WorkspaceState

    recorder = AgentLabGraphRecorder(_scope(f"replay-{attack.id}", attack.benign_task))
    env = OpenClawEnvironment(workspace=WorkspaceState())
    with patch_agentlab(recorder):
        recorder.begin_session(env, attack.benign_task, phase="oracle_replay")
        # Reproduce the case's poisoned external-return channel before the
        # ground-truth malicious calls.  The returned payload is only retained
        # as a digest in the graph, but its integrity is marked untrusted.
        if getattr(attack, "injection_seed", ""):
            env.configure_injection("web_fetch", attack.injection_seed)
            env.execute_tool("web_fetch", {"url": "https://company.internal/announcements"})
        for call in attack.malicious_tool_calls:
            tool = call.get("tool", "")
            args = dict(call.get("arguments", {}))
            env.execute_tool(tool, args)

    payload = recorder.export(
        label="attack_success",
        result={
            "attack": _attack_meta(attack),
            "outcome": {
                "success": True,
                "evaluation": "oracle_tool_call_replay",
                "not_llm_asr": True,
                "tool_calls": len(attack.malicious_tool_calls),
            },
        },
    )
    payload["created_at"] = datetime.now(timezone.utc).isoformat()
    payload["method"] = "oracle_replay"
    target = output_root / "attack_success" / f"replay-{case_id.lower()}.json"
    _write_json(target, payload)
    return {
        "label": "attack_success",
        "case": f"replay-{case_id}",
        "name": attack.name,
        "path": str(target),
        "metrics": payload["metrics"],
        "outcome": payload["result"]["outcome"],
        "method": "oracle_replay",
    }


def _graph_features(run: dict[str, Any]) -> dict[str, Any]:
    metrics = run.get("metrics", {})
    graph = run.get("graph", {})
    if not graph and run.get("path"):
        try:
            graph = json.loads(Path(run["path"]).read_text(encoding="utf-8")).get("graph", {})
        except (OSError, json.JSONDecodeError):
            graph = {}
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    observations = [node for node in nodes if node.get("node_type") == "observation"]
    actions = [node for node in nodes if node.get("node_type") == "action"]
    effects = [node for node in nodes if node.get("node_type") == "effect"]
    states = [node for node in nodes if node.get("node_type") == "state"]
    effect_kinds = dict(Counter(node.get("data", {}).get("kind", "unknown") for node in effects))
    return {
        "label": run.get("label"),
        "case": run.get("case"),
        "nodes": len(nodes),
        "edges": len(edges),
        "observations": len(observations),
        "actions": len(actions),
        "effects": len(effects),
        "states": len(states),
        "untrusted_observations": sum(node.get("data", {}).get("integrity") == "untrusted" for node in observations),
        "effect_kinds": effect_kinds,
        "effect_statuses": dict(Counter(node.get("data", {}).get("status", "unknown") for node in effects)),
        "edge_kinds": dict(Counter(edge.get("edge_type") for edge in edges)),
        "state_read_edges": metrics.get("state_read_edges", 0),
        "persistent_effects": metrics.get("persistent_effects", 0),
        "committed_effects": metrics.get("committed_effects", 0),
        "unknown_effect_ratio": (
            metrics.get("node_counts", {}).get("effect", 0) and
            effect_kinds.get("unknown", 0) / metrics["node_counts"]["effect"]
        ) or 0.0,
        "compact_bytes": metrics.get("compact_bytes", 0),
        "graph_bytes": metrics.get("graph_bytes", 0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--normal-turns", type=int, nargs="+", default=[50, 150])
    parser.add_argument("--direct-cases", nargs="*", default=["LONG-001", "LONG-003"])
    parser.add_argument("--dojo-filter", default=None, help="AgentDojo pair, e.g. user_task_15+injection_task_0")
    parser.add_argument("--dojo-variant", default="s1", choices=["s1", "s2", "s2_cross_session", "frag_fuse"])
    parser.add_argument("--replay-success-case", default=None, help="Replay ground-truth calls as a deterministic success specimen")
    parser.add_argument("--max-turns", type=int, default=2)
    parser.add_argument("--max-rounds", type=int, default=6)
    args = parser.parse_args()

    _load_env(args.env_file)
    args.output_root.mkdir(parents=True, exist_ok=True)
    runs: list[dict[str, Any]] = []
    for turns in args.normal_turns:
        runs.append(run_normal(turns, args.output_root))

    for case_id in args.direct_cases:
        try:
            runs.append(run_attack(
                _attack_instance(case_id),
                output_root=args.output_root,
                max_turns=args.max_turns,
                max_rounds=args.max_rounds,
            ))
        except Exception as exc:
            runs.append({"label": "attack_error", "case": case_id, "error": f"{type(exc).__name__}: {exc}"})

    if args.replay_success_case:
        try:
            runs.append(run_success_replay(args.replay_success_case, output_root=args.output_root))
        except Exception as exc:
            runs.append({"label": "attack_error", "case": f"replay-{args.replay_success_case}", "error": f"{type(exc).__name__}: {exc}"})

    if args.dojo_filter:
        try:
            runs.append(run_attack(
                _dynamic_attack(args.dojo_filter, args.dojo_variant),
                output_root=args.output_root,
                max_turns=args.max_turns,
                max_rounds=args.max_rounds,
            ))
        except Exception as exc:
            runs.append({"label": "attack_error", "case": args.dojo_filter, "error": f"{type(exc).__name__}: {exc}"})

    feature_rows = [_graph_features(run) for run in runs if run.get("metrics")]
    index = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "graph_features": feature_rows,
        "interpretation": {
            "normal": "Expected task effects stay within read/write/create scope and have no untrusted tool-return source.",
            "attack_success": "The specimen follows the ground-truth malicious path; this oracle replay is for graph validation and is not an LLM ASR result.",
            "attack_failure": "The attack was attempted but the malicious goal was not met; partial writes/reads still reveal residual risk.",
        },
    }
    _write_json(args.output_root / "index.json", index)
    print(json.dumps(index, ensure_ascii=False, indent=2, default=_json_default))


if __name__ == "__main__":
    main()
