#!/usr/bin/env python3
"""Freeze the V0-to-V1 comparison without conflating review with detection."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V0 = ROOT / "experiments/large_scale_authorization_v0_results.json"
V1 = ROOT / "experiments/large_scale_authorization_v1_results.json"
OUT = ROOT / "experiments/programmatic_rule_completion_v1_summary.json"


def metrics(rows: list[dict]) -> dict:
    attack = [row for row in rows if row["group"] == "attack_positive"]
    normal = [row for row in rows if row["group"] == "clean_normal"]
    target_alert = sum("alert" in row["target_verdicts"] for row in attack)
    target_review = sum("review" in row["target_verdicts"] for row in attack)
    target_unmatched = sum(not row["target_verdicts"] for row in attack)
    normal_alert = sum(row["alert_calls"] > 0 for row in normal)
    normal_review = sum(row["review_calls"] > 0 for row in normal)
    normal_clear = sum(not row["alert_calls"] and not row["review_calls"] for row in normal)
    return {"attack_cases": len(attack), "target_alert_cases": target_alert,
            "target_review_cases": target_review, "target_unmatched_cases": target_unmatched,
            "target_alert_rate_among_matchable": target_alert / (len(attack) - target_unmatched),
            "target_alert_rate_all_attacks": target_alert / len(attack),
            "normal_cases": len(normal), "normal_explicit_alert_cases": normal_alert,
            "normal_review_cases": normal_review, "normal_clear_cases": normal_clear,
            "normal_success_if_all_nonallow_blocked": normal_clear / len(normal)}


def main() -> None:
    if OUT.exists():
        raise FileExistsError(OUT)
    v0 = json.loads(V0.read_text(encoding="utf-8"))["rows"]
    v1 = json.loads(V1.read_text(encoding="utf-8"))["rows"]
    old_engineering = {"unmapped_tool_effect", "operation_not_extracted_from_user_request"}
    remaining_old = Counter(d["reason"] for row in v1 for d in row["decisions"]
                            if d["reason"] in old_engineering)
    output = {"schema": "gwg-programmatic-rule-completion-v1-summary",
              "v0": metrics(v0), "v1": metrics(v1),
              "remaining_engineering_reason_counts": dict(remaining_old),
              "interpretation": {
                  "normal_cases_removed_from_review": metrics(v0)["normal_review_cases"] - metrics(v1)["normal_review_cases"],
                  "attack_target_alert_gain": metrics(v1)["target_alert_cases"] - metrics(v0)["target_alert_cases"],
                  "rule_frontier": "remaining target reviews have contextual or parameter-binding reasons"
              }}
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
