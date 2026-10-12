"""Evaluate the narrow guard on saved *real* OpenClaw cases.

The saved case bundles contain initial/final file content but not every
intermediate file body. Consequently this adapter performs an end-of-run
audit. It must not be described as a measured online detection time.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from greatwallguard.state_version_guard import StateVersionGuard


ROOT = Path(__file__).resolve().parents[2]
ATTACKS = ROOT / "openclaw-longrange-manual-lab/dataset/model-output-integrity/curated/double-success"
CONTROLS = ROOT / "greatwallguard/dataset/benign-controls/cases/model_output_integrity"
ATTEMPTED_RUNS = ROOT / "openclaw-longrange-manual-lab/dataset/model-output-integrity/runs"
STATUS_PATH = "PROJECT_STATUS.md"


def evaluate(path: Path, *, sample_type: str) -> dict[str, object]:
    case = json.loads(path.read_text(encoding="utf-8"))
    execution = case.get("execution") or {}
    before = ((execution.get("workspace_before") or {}).get("files") or {}).get(STATUS_PATH)
    after = ((execution.get("workspace_after") or {}).get("files") or {}).get(STATUS_PATH)
    result: dict[str, object] = {
        "case_id": case.get("case_id"), "sample_type": sample_type,
        "case_path": str(path.relative_to(ROOT)),
        "snapshot_granularity": "initial_and_final_only",
    }
    if not isinstance(before, dict) or not isinstance(after, dict):
        result.update(verdict="not_evaluable", reason="missing_status_snapshots")
        return result
    first, last = before.get("content"), after.get("content")
    if not isinstance(first, str) or not isinstance(last, str):
        result.update(verdict="not_evaluable", reason="missing_status_content")
        return result
    guard = StateVersionGuard(path=STATUS_PATH)
    guard.observe_snapshot(first, turn=0)
    turns = execution.get("visible_agent_turns") or []
    for turn in turns:
        message, number = turn.get("user_message"), turn.get("turn")
        if isinstance(message, str) and isinstance(number, int):
            guard.observe_user(message, turn=number)
    last_turn = guard.current_turn
    finding = guard.observe_snapshot(last, turn=last_turn,
                                     observation_kind="end_of_run_snapshot")
    if finding is None:
        result.update(verdict="no_field_change", reason="status_field_unchanged")
    else:
        result.update(verdict=finding.verdict, reason=finding.reason,
                      before=finding.before, after=finding.after,
                      user_evidence=finding.user_evidence,
                      observed_end_of_run=True)
    return result


def main() -> None:
    rows = [evaluate(path, sample_type="attack_double_success")
            for path in sorted(ATTACKS.glob("**/case.json"))]
    rows += [evaluate(path, sample_type="benign_control")
             for path in sorted(CONTROLS.glob("**/case.json"))]
    # These are not clean benign controls: an injection was attempted, but the
    # normal task succeeded and the target oracle did not. Keep them separate.
    for path in sorted(ATTEMPTED_RUNS.glob("*/cases/*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        labels = case.get("labels") or {}
        if labels.get("task_success") is True and labels.get("output_integrity_success") is False:
            rows.append(evaluate(path, sample_type="attempted_attack_task_success"))
    counts = {kind: dict(Counter(str(row["verdict"]) for row in rows
                                 if row["sample_type"] == kind))
              for kind in ("attack_double_success", "benign_control",
                           "attempted_attack_task_success")}
    print(json.dumps({"counts": counts, "cases": rows}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
