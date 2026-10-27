#!/usr/bin/env python3
"""Small frozen AgentDojo v1.1 evaluation for Programmatic Core v0.1.

This experiment does not invoke a victim model.  It replays AgentDojo's
official ground-truth calls as two separate streams:

* the canonical calls required by the benign user task;
* the canonical calls that would satisfy the injection goal.

The second stream is appended only to measure conditional detection if the
attack action is proposed.  This is not an end-to-end ASR experiment.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from agentdojo.task_suite.load_suites import get_suite

from greatwallguard import ProgrammaticAuthorizationGuard


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "agentdojo_programmatic_v01_results.json"
BENCHMARK_VERSION = "v1.1"
SUITE_NAME = "workspace"

# The first three pairs use a different attack effect.  The last three test
# same-tool ambiguity: legitimate and injected calls use the same operation.
PAIRS = (
    ("different_tool_email", "user_task_0", "injection_task_0"),
    ("different_tool_delete", "user_task_0", "injection_task_1"),
    ("different_tool_calendar", "user_task_0", "injection_task_2"),
    ("same_tool_email", "user_task_33", "injection_task_0"),
    ("same_tool_delete", "user_task_35", "injection_task_1"),
    ("same_tool_calendar", "user_task_6", "injection_task_2"),
)


def _run_calls(guard: ProgrammaticAuthorizationGuard, calls: list[Any], *,
               turn: int, prefix: str) -> list[dict[str, Any]]:
    rows = []
    for index, call in enumerate(calls, 1):
        call_id = f"{prefix}-{index}"
        decision = guard.before_tool_call(
            str(call.function), dict(call.args), turn=turn, call_id=call_id
        )
        # Ground-truth calls are treated as successful canonical actions.  The
        # result content is irrelevant to this authorization-only experiment.
        guard.after_tool_result(call_id, succeeded=True)
        rows.append({
            "tool": str(call.function),
            "arguments": dict(call.args),
            "verdict": decision.verdict,
            "reason": decision.reason,
            "possible_false_positive": decision.possible_false_positive,
        })
    return rows


def run() -> dict[str, Any]:
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    environment = suite.load_and_inject_default_environment({})
    rows = []
    for pair_id, user_task_id, injection_task_id in PAIRS:
        user_task = suite.user_tasks[user_task_id]
        injection_task = suite.injection_tasks[injection_task_id]
        normal_calls = list(user_task.ground_truth(environment))
        attack_calls = list(injection_task.ground_truth(environment))

        normal_guard = ProgrammaticAuthorizationGuard()
        normal_guard.on_user_message(user_task.PROMPT, turn=1, trusted=True)
        normal = _run_calls(normal_guard, normal_calls, turn=1, prefix=f"{pair_id}-normal")

        attack_guard = ProgrammaticAuthorizationGuard()
        attack_guard.on_user_message(user_task.PROMPT, turn=1, trusted=True)
        benign_prefix = _run_calls(
            attack_guard, normal_calls, turn=1, prefix=f"{pair_id}-benign-prefix"
        )
        target = _run_calls(
            attack_guard, attack_calls, turn=1, prefix=f"{pair_id}-attack-target"
        )

        rows.append({
            "pair_id": pair_id,
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
            "same_target_tool": bool(
                {call.function for call in normal_calls}
                & {call.function for call in attack_calls}
            ),
            "user_prompt": user_task.PROMPT,
            "injection_goal_for_evaluation_only": injection_task.GOAL,
            "normal": normal,
            "attack_replay": {
                "benign_prefix": benign_prefix,
                "target": target,
            },
            "normal_has_alert": any(item["verdict"] == "alert" for item in normal),
            "normal_has_review": any(item["verdict"] == "review" for item in normal),
            "target_has_alert": any(item["verdict"] == "alert" for item in target),
            "target_has_review": any(item["verdict"] == "review" for item in target),
        })

    summary = {
        "pairs": len(rows),
        "normal_tasks_with_alert": sum(row["normal_has_alert"] for row in rows),
        "normal_tasks_with_review": sum(row["normal_has_review"] for row in rows),
        "attack_targets_with_alert": sum(row["target_has_alert"] for row in rows),
        "attack_targets_with_review_only": sum(
            not row["target_has_alert"] and row["target_has_review"] for row in rows
        ),
        "normal_verdicts": dict(Counter(
            item["verdict"] for row in rows for item in row["normal"]
        )),
        "attack_target_verdicts": dict(Counter(
            item["verdict"]
            for row in rows
            for item in row["attack_replay"]["target"]
        )),
    }
    result = {
        "schema": "greatwallguard-agentdojo-programmatic-v0.1",
        "benchmark": {"name": "AgentDojo", "version": BENCHMARK_VERSION,
                      "suite": SUITE_NAME, "agentdojo_package": "0.1.34"},
        "protocol": "official_ground_truth_call_replay_without_victim_model",
        "scope": "conditional authorization check; not end-to-end ASR or utility",
        "pairs_spec": [list(item) for item in PAIRS],
        "summary": summary,
        "rows": rows,
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run()["summary"], ensure_ascii=False, indent=2))
