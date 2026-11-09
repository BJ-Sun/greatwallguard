#!/usr/bin/env python3
"""Full canonical-trace evaluation of GreatWallGuard stages one and two.

AgentDyn authorization DAGs are compiled once from trusted prompts and tool
metadata, then cached per task.  Evaluation replays official normal ground
truth and conditionally audits official injection targets.  It does not claim
victim-model end-to-end ASR/utility; that is a separate experiment layer.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
from typing import Any

from agentdojo.task_suite.load_suites import get_suite

from agentdyn_authorization_runtime_v05 import (
    OUTBOUND_OBSERVATIONS, PASSIVE_OBSERVATIONS, _execute, _tool_succeeded,
)
from agentdyn_intent_dag_pilot import EFFECT_TOOLS, _metadata
from stage2_agentdyn_contracts import (
    CAPABILITY_RULES, PROVISIONAL_EFFECT_TOOLS, SOURCE_ALIASES,
)
from greatwallguard import (
    AuthorizationDAG, AuthorizationRuntime, ConstrainedIntentDAGCompiler,
    IntentCompilationError, ObservationContract, OpenAICompatibleIntentBackend,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "experiments" / "stage2_full"
AGENTDYN_CACHE = RESULT_ROOT / "agentdyn_authorizations_v2"
AGENTDYN_RESULT = RESULT_ROOT / "agentdyn_results.json"
AGENTDYN_SUITES = ("shopping", "github", "dailylife")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _cache_path(suite: str, task_id: str) -> Path:
    return AGENTDYN_CACHE / suite / f"{task_id}.json"


def compile_agentdyn(*, model: str = "deepseek-chat",
                     retry_errors: bool = False) -> dict[str, int]:
    if not os.getenv("DEEPSEEK_API_KEY"):
        local_env = ROOT.parent / "openclaw-longrange-lab" / ".env"
        if local_env.exists():
            for line in local_env.read_text(encoding="utf-8").splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    os.environ["DEEPSEEK_API_KEY"] = line.split("=", 1)[1].strip().strip("\"'")
                    break
    backend = OpenAICompatibleIntentBackend(
        model=model, api_key_env="DEEPSEEK_API_KEY",
    )
    counts = Counter()
    for suite_name in AGENTDYN_SUITES:
        suite = get_suite("v1.2.2", suite_name)
        contracts, observations = _metadata(suite)
        compiler = ConstrainedIntentDAGCompiler(
            contracts, observations, backend, max_repair_attempts=2,
        )
        for task_id, task in suite.user_tasks.items():
            path = _cache_path(suite_name, task_id)
            if path.exists():
                cached = json.loads(path.read_text())
                if not retry_errors or cached.get("status") == "compiled":
                    counts["cached"] += 1
                    continue
            try:
                graph = compiler.compile(
                    task.PROMPT,
                    version=f"agentdyn-full-v1:{suite_name}:{task_id}",
                )
                row = {
                    "status": "compiled", "suite": suite_name,
                    "task_id": task_id, "prompt": task.PROMPT,
                    "model": model, "authorization_dag": graph.to_dict(),
                }
                counts["compiled"] += 1
            except (IntentCompilationError, RuntimeError, KeyError) as error:
                row = {
                    "status": "compile_error", "suite": suite_name,
                    "task_id": task_id, "prompt": task.PROMPT,
                    "model": model, "error_type": type(error).__name__,
                    "error": str(error),
                }
                counts["compile_error"] += 1
            _write_json(path, row)
    return dict(counts)


def _runtime(graph: AuthorizationDAG, prompt: str, suite) -> AuthorizationRuntime:
    observation_contracts = []
    for tool in suite.tools:
        if tool.name in EFFECT_TOOLS:
            continue
        if tool.name in OUTBOUND_OBSERVATIONS:
            mode = "outbound"
        elif tool.name.startswith(("login_", "switch_")):
            mode = "scoped"
        else:
            mode = "passive"
        observation_contracts.append(ObservationContract(tool.name, mode))
    return AuthorizationRuntime(
        graph, user_message=prompt, source_aliases=SOURCE_ALIASES,
        capability_rules=CAPABILITY_RULES,
        observation_contracts=observation_contracts,
        known_effect_tools=EFFECT_TOOLS,
        provisional_effect_tools=PROVISIONAL_EFFECT_TOOLS,
    )


def _decision(decision, tool: str, arguments: dict[str, Any], role: str) -> dict:
    return {
        "tool": tool, "arguments": arguments, "role": role,
        "verdict": decision.verdict, "reason": decision.reason,
        "field": decision.field, "effect_id": decision.effect_id,
        "proof_nodes": list(decision.proof_nodes),
        "proof_evidence": list(decision.proof_evidence),
        "core_ops": list(decision.core_ops),
        "review_type": decision.review_type,
        "delegation_id": decision.delegation_id,
        "missing_evidence": list(decision.missing_evidence),
    }


def _execute_agentdyn(suite, environment, call):
    """Execute a canonical call with documented AgentDyn schema aliases.

    AgentDyn v1.2.2 contains one shopping ground-truth call using the legacy
    ``discount`` field while the installed tool schema exposes
    ``discount_code``.  The guard must audit the canonical arguments as they
    are written; this adapter only repairs the benchmark execution boundary so
    later observations are not lost.
    """
    if str(call.function) == "checkout_selected_cart":
        arguments = dict(call.args)
        if "discount" in arguments and "discount_code" not in arguments:
            arguments["discount_code"] = arguments.pop("discount")
        function = next(item for item in suite.tools if item.name == str(call.function))
        dependencies = {
            name: dependency.extract_dep_from_env(environment)
            for name, dependency in function.dependencies.items()
        }
        return function.run(**dependencies, **arguments)
    return _execute(suite, environment, call)


def _outcome(decisions: list[dict]) -> str:
    verdicts = {item["verdict"] for item in decisions}
    return "alert" if "alert" in verdicts else "review" if "review" in verdicts else "allow"


def evaluate_agentdyn() -> dict:
    normal_rows = []
    attack_rows = []
    compile_errors = []
    for suite_name in AGENTDYN_SUITES:
        suite = get_suite("v1.2.2", suite_name)
        for task_id, task in suite.user_tasks.items():
            cached = json.loads(_cache_path(suite_name, task_id).read_text())
            if cached["status"] != "compiled":
                compile_errors.append(cached)
                continue
            graph = AuthorizationDAG.from_dict(cached["authorization_dag"])
            runtime = _runtime(graph, task.PROMPT, suite)
            environment = suite.load_and_inject_default_environment({})
            decisions = []
            execution_error = None
            for index, call in enumerate(task.ground_truth(environment), 1):
                tool, arguments = str(call.function), dict(call.args)
                is_effect = tool in EFFECT_TOOLS
                role = "effect" if is_effect else "observation"
                call_id = f"normal:{suite_name}:{task_id}:{index}"
                decision = runtime.authorize_tool_call(
                    call_id, tool, arguments, read_only=not is_effect,
                )
                decisions.append(_decision(decision, tool, arguments, role))
                try:
                    result = _execute_agentdyn(suite, environment, call)
                except Exception as error:
                    execution_error = {
                        "call_id": call_id, "tool": tool,
                        "error_type": type(error).__name__, "error": str(error),
                    }
                    if decision.verdict == "allow":
                        runtime.commit_tool_result(call_id, succeeded=False)
                    break
                if decision.verdict == "allow":
                    runtime.commit_tool_result(
                        call_id, succeeded=_tool_succeeded(result), result=result,
                    )
                else:
                    # Conditional replay measures evidence coverage after a
                    # pause; a live runtime would stop and request review.
                    runtime.observe_tool_result(
                        call_id, tool, result, arguments=arguments,
                    )
            normal_rows.append({
                "suite": suite_name, "task_id": task_id,
                "prompt": task.PROMPT, "outcome": _outcome(decisions),
                "execution_error": execution_error, "decisions": decisions,
            })

            snapshot = runtime.snapshot()
            snapshot["consumed"] = {}
            snapshot["consumed_bindings"] = {}
            snapshot["revoked"] = []
            for injection_id, injection in suite.injection_tasks.items():
                attack_runtime = AuthorizationRuntime.from_snapshot(snapshot)
                attack_decisions = []
                attack_environment = suite.load_and_inject_default_environment({})
                for index, call in enumerate(injection.ground_truth(attack_environment), 1):
                    tool, arguments = str(call.function), dict(call.args)
                    decision = attack_runtime.authorize_tool_call(
                        f"attack:{suite_name}:{task_id}:{injection_id}:{index}",
                        tool, arguments, read_only=tool not in EFFECT_TOOLS,
                    )
                    attack_decisions.append(_decision(
                        decision, tool, arguments, "attack_target",
                    ))
                attack_rows.append({
                    "suite": suite_name, "task_id": task_id,
                    "injection_task_id": injection_id,
                    "outcome": _outcome(attack_decisions),
                    "decisions": attack_decisions,
                })

    normal_counts = Counter(row["outcome"] for row in normal_rows)
    attack_counts = Counter(row["outcome"] for row in attack_rows)
    review_reasons = Counter(
        call["reason"] for row in normal_rows for call in row["decisions"]
        if call["verdict"] == "review"
    )
    attack_by_suite = defaultdict(Counter)
    for row in attack_rows:
        attack_by_suite[row["suite"]][row["outcome"]] += 1
    result = {
        "schema": "greatwallguard-stage2-agentdyn-full-v1",
        "protocol": (
            "all 60 AgentDyn v1.2.2 normal canonical traces and all 560 "
            "user-task/injection-target pairs; authorization compiled only from trusted "
            "prompt and deployment schemas; conditional replay, no victim LLM"
        ),
        "summary": {
            "configured_tasks": 60,
            "compiled_tasks": len(normal_rows),
            "compile_errors": len(compile_errors),
            "normal_outcomes": dict(normal_counts),
            "normal_execution_errors": sum(
                row["execution_error"] is not None for row in normal_rows
            ),
            "normal_review_reasons": dict(review_reasons),
            "attack_pairs": len(attack_rows),
            "attack_outcomes": dict(attack_counts),
            "attack_by_suite": {
                suite: dict(counts) for suite, counts in attack_by_suite.items()
            },
        },
        "compile_error_rows": compile_errors,
        "normal_rows": normal_rows,
        "attack_rows": attack_rows,
    }
    _write_json(AGENTDYN_RESULT, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("compile-agentdyn", "evaluate-agentdyn"))
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--retry-errors", action="store_true")
    args = parser.parse_args()
    if args.command == "compile-agentdyn":
        print(json.dumps(compile_agentdyn(
            model=args.model, retry_errors=args.retry_errors,
        ), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(evaluate_agentdyn()["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
