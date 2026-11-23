#!/usr/bin/env python3
"""Small real Stage-1/2 replay before the GreatWallBench full run."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from greatwallguard import (
    AuthorizationDAG, AuthorizationRuntime, AuthorizationTimeline,
    ConstrainedAuthorizationUpdateCompiler, ConstrainedIntentDAGCompiler,
    BoundedDerivedEffectPolicy, DagDecision, OpenAICompatibleIntentBackend,
    PersistentStateMonitor,
)

from benchmark_contracts import EFFECTS, contracts
from dataset_adapter import ReplayCase, iter_cases


HERE = Path(__file__).resolve().parent
CACHE = HERE / "authorization_cache"
UPDATE_CACHE = HERE / "authorization_update_cache"
OUT = HERE / "smoke_stage12_results.json"
COMPILER_PROFILE = "greatwallbench-turn-timeline-v3"
PLATFORM_BOOTSTRAP_OBJECTS = frozenset({
    "AGENTS.md", "BOOTSTRAP.md", "IDENTITY.md", "SOUL.md", "USER.md",
})


def _load_key() -> None:
    if os.getenv("DEEPSEEK_API_KEY"):
        return
    candidates = (
        HERE.parents[2] / "openclaw-longrange-lab/.env",
        HERE.parents[2] / "attack-generation/openclaw-agentlab/.env",
    )
    for path in candidates:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("DEEPSEEK_API_KEY="):
                os.environ["DEEPSEEK_API_KEY"] = line.split("=", 1)[1].strip().strip("\"'")
                return
    raise RuntimeError("DEEPSEEK_API_KEY is unavailable")


def _request(case: ReplayCase) -> str:
    return "\n".join(
        f"[Trusted user turn {index}] {message}"
        for index, message in enumerate(case.trusted_messages, 1)
    )


def _cache_key(case: ReplayCase, message: str) -> str:
    tools = case.tool_contract.get("tools") or []
    payload = json.dumps(
        {"compiler_profile": COMPILER_PROFILE,
         "request": message, "tools": tools},
        ensure_ascii=False, sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _compile_turn(case: ReplayCase, message: str, turn: int, backend) -> AuthorizationDAG:
    key = _cache_key(case, message)
    path = CACHE / f"{key}.json"
    if path.is_file():
        return AuthorizationDAG.from_dict(json.loads(path.read_text())["authorization_dag"])
    effect_contracts, observation_tools, _ = contracts((case.tool_contract,))
    compiler = ConstrainedIntentDAGCompiler(
        effect_contracts, observation_tools, backend, max_repair_attempts=2,
        allow_partial=True,
    )
    graph = compiler.compile(
        message, version=f"greatwallbench:{case.case_id}:turn-{turn}",
    )
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "case_id": case.case_id,
        "request_sha256": hashlib.sha256(message.encode()).hexdigest(),
        "authorization_dag": graph.to_dict(),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return graph


def _decision_dict(event, decision, *, target: bool) -> dict[str, Any]:
    return {
        "call_id": event.payload["call_id"],
        "turn": event.turn,
        "tool": event.payload["tool"],
        "verdict": decision.verdict,
        "reason": decision.reason,
        "field": decision.field,
        "target_call": target,
    }


def replay(case: ReplayCase, backend) -> dict[str, Any]:
    effect_contracts, observation_tools, observation_contracts = contracts((case.tool_contract,))
    intent_compiler = ConstrainedIntentDAGCompiler(
        effect_contracts, observation_tools, backend,
        max_repair_attempts=2, allow_partial=True,
    )
    update_compiler = ConstrainedAuthorizationUpdateCompiler(
        intent_compiler, backend,
    )
    graph = AuthorizationDAG(version=f"greatwallbench:{case.case_id}:timeline")
    runtime = AuthorizationRuntime(
        graph,
        user_message="",
        observation_contracts=observation_contracts,
        known_effect_tools=(contract.tool for contract in effect_contracts),
        provisional_effect_tools=("workspace_state_change",),
        derived_effect_policy=BoundedDerivedEffectPolicy(),
    )
    timeline = AuthorizationTimeline(runtime)
    state_monitor = PersistentStateMonitor(runtime, trust_initial_state=True)
    results = {
        event.payload["call_id"]: event
        for event in case.events if event.kind == "tool_result"
    }
    decisions = []
    for event in case.events:
        if event.kind == "user_message":
            message = str(event.payload.get("message") or "")
            plan = update_compiler.compile(
                trusted_message=message, runtime=runtime, turn=event.turn,
            )
            update_compiler.apply(
                plan=plan, timeline=timeline, turn=event.turn,
                trusted_message=message,
            )
            continue
        if event.kind == "state_read":
            path = str(event.payload.get("path") or "workspace://unknown")
            version_id = str(
                event.payload.get("sha256")
                or event.payload.get("version_hint")
                or f"read:{event.turn}:{event.order}"
            )
            state_monitor.record_read(
                call_id=f"state-read:{event.turn}:{event.order}",
                tool="workspace_state_read", object_id=path,
                version_id=version_id, value={
                    "path": path,
                    "sha256": event.payload.get("sha256"),
                    "bytes": event.payload.get("bytes"),
                }, arguments={"path": path},
            )
            continue
        if event.kind == "state_change":
            path = str(event.payload.get("path") or "workspace://unknown")
            operation = str(event.payload.get("op") or "update")
            call_id = f"state-change:{event.turn}:{event.order}"
            arguments = {
                "path": path,
                "operation": operation,
                "content": event.payload.get("after_content"),
                "before_sha256": event.payload.get("before_sha256"),
                "after_sha256": event.payload.get("after_sha256"),
                "visibility": "local_workspace",
                "lifetime": "persistent",
            }
            platform_bootstrap = (
                path in PLATFORM_BOOTSTRAP_OBJECTS
                and operation == "create"
                and event.payload.get("before_sha256") is None
            )
            if platform_bootstrap:
                decision = DagDecision("allow", "trusted_platform_bootstrap")
            else:
                decision = runtime.authorize_tool_call(
                    call_id, "workspace_state_change", arguments,
                )
                decisions.append({
                    "call_id": call_id, "turn": event.turn,
                    "tool": "workspace_state_change", "verdict": decision.verdict,
                    "reason": decision.reason, "field": decision.field,
                    "target_call": False, "state_object": path,
                })
            after = str(
                event.payload.get("after_sha256")
                or event.payload.get("version")
                or f"after:{event.turn}:{event.order}"
            )
            before_raw = event.payload.get("before_sha256")
            before = str(before_raw) if before_raw is not None else None
            state_monitor.record_change(
                object_id=path, before_version_id=before,
                after_version_id=after, created_by_call_id=call_id,
                value={
                    "sha256": event.payload.get("after_sha256"),
                    "bytes": event.payload.get("after_bytes"),
                    "content": event.payload.get("after_content"),
                    "operation": operation,
                }, decision=decision,
            )
            if decision.verdict == "allow" and not platform_bootstrap:
                runtime.commit_tool_result(call_id, succeeded=True)
            continue
        if event.kind != "tool_call":
            continue
        call_id = str(event.payload["call_id"])
        tool = str(event.payload["tool"])
        args = dict(event.payload["arguments"])
        decision = runtime.authorize_tool_call(
            call_id, tool, args, read_only=tool not in EFFECTS,
        )
        decisions.append(_decision_dict(
            event, decision, target=call_id in case.label.target_call_ids,
        ))
        result_event = results.get(call_id)
        if result_event is None:
            continue
        succeeded = not bool(result_event.payload.get("error")) and not bool(
            result_event.payload.get("shadow_blocked")
        )
        if decision.verdict == "allow":
            runtime.commit_tool_result(
                call_id, succeeded=succeeded,
                result=result_event.payload.get("result"),
            )
        else:
            runtime.observe_tool_result(
                call_id, tool, result_event.payload.get("result"), arguments=args,
            )
    target = [row for row in decisions if row["target_call"]]
    state_decisions = [
        row for row in decisions if row["tool"] == "workspace_state_change"
    ]
    return {
        "case_id": case.case_id,
        "group": case.label.group,
        "target": case.label.target,
        "protocol": "turn-ordered authorization timeline frozen-trace replay",
        "outcome": (
            "alert" if any(row["verdict"] == "alert" for row in decisions) else
            "review" if any(row["verdict"] == "review" for row in decisions) else
            "allow"
        ),
        "target_outcome": (
            (
                "alert" if any(row["verdict"] == "alert" for row in state_decisions) else
                "review" if any(row["verdict"] == "review" for row in state_decisions) else
                "allow" if state_decisions else "target_not_matched"
            ) if case.label.target == "model_output_integrity" else
            "alert" if any(row["verdict"] == "alert" for row in target) else
            "review" if any(row["verdict"] == "review" for row in target) else
            "allow" if target else "target_not_matched"
        ),
        "decisions": decisions,
        "authorization_updates": [
            {
                "turn": item.turn,
                "message_sha256": item.message_sha256,
                "added_effect_ids": list(item.added_effect_ids),
                "revoked_effect_ids": list(item.revoked_effect_ids),
            }
            for item in timeline.records
        ],
    }


def _sample(*, full: bool = False) -> list[ReplayCase]:
    if full:
        return list(iter_cases())
    selected = []
    seen: set[tuple[str, str]] = set()
    for case in iter_cases():
        key = (case.label.group, case.label.target)
        if key not in seen:
            seen.add(key)
            selected.append(case)
    return selected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    _load_key()
    remote_backend = OpenAICompatibleIntentBackend(
        model=args.model, api_key_env="DEEPSEEK_API_KEY",
    )
    class CachedBackend:
        def generate(self, *, system_prompt, user_prompt):
            key = hashlib.sha256(json.dumps(
                {"system": system_prompt, "user": user_prompt},
                ensure_ascii=False, sort_keys=True,
            ).encode()).hexdigest()
            path = UPDATE_CACHE / f"{key}.json"
            if path.is_file():
                return json.loads(path.read_text(encoding="utf-8"))
            value = remote_backend.generate(
                system_prompt=system_prompt, user_prompt=user_prompt,
            )
            UPDATE_CACHE.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return value
    backend = CachedBackend()
    rows = []
    failures = []
    cases = _sample(full=args.full)
    for index, case in enumerate(cases, 1):
        try:
            rows.append(replay(case, backend))
        except Exception as error:
            failures.append({
                "case_id": case.case_id,
                "group": case.label.group,
                "target": case.label.target,
                "error_type": type(error).__name__,
                "error": str(error),
            })
        if args.full:
            print(json.dumps({
                "progress": f"{index}/{len(cases)}",
                "case_id": case.case_id,
                "completed": len(rows),
                "failures": len(failures),
            }, ensure_ascii=False), flush=True)
    summary = {
        "cases": len(rows),
        "failures": len(failures),
        "normal_outcomes": dict(Counter(
            row["outcome"] for row in rows if row["group"] == "normal"
        )),
        "attack_target_outcomes": dict(Counter(
            row["target_outcome"] for row in rows if row["group"] == "attack"
        )),
    }
    output_path = HERE / ("full_stage12_results.json" if args.full else OUT.name)
    output_path.write_text(json.dumps({
        "schema": (
            "greatwallbench-stage12-full-v1" if args.full
            else "greatwallbench-stage12-smoke-v1"
        ),
        "summary": summary,
        "failures": failures,
        "rows": rows,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
