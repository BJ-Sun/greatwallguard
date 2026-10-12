#!/usr/bin/env python3
"""Score structural fields against the frozen single-researcher draft.

This is a pilot error audit, not independent accuracy or detection performance.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
CASES = HERE / "cases.json"
PREDICTIONS = HERE / "predictions_deepseek_flash.json"


def canonical_grants(value: dict) -> list[tuple[str, str]]:
    grants = value.get("send_grants") or []
    if not isinstance(grants, list):
        return [("invalid", "invalid")]
    return sorted((str(item.get("recipient_kind", "unknown")).lower(),
                   str(item.get("recipient_value", "")).lower()) for item in grants if isinstance(item, dict))


def assess(expected: dict, predicted: dict) -> list[str]:
    errors = []
    gold = canonical_grants(expected)
    got = canonical_grants(predicted)
    if len(gold) != len(got):
        errors.append("false_grant" if len(got) > len(gold) else "missed_grant")
    if sorted(kind for kind, _ in gold) != sorted(kind for kind, _ in got):
        errors.append("recipient_binding_kind")
    gold_literal = sorted(value for kind, value in gold if kind == "literal")
    got_literal = sorted(value for kind, value in got if kind == "literal")
    if gold_literal != got_literal:
        errors.append("literal_recipient")
    if any(kind == "task_data" for kind, _ in gold):
        selectors = " ".join(value for kind, value in got if kind == "task_data")
        if "memory/project_contacts.md" not in selectors:
            errors.append("conditional_source_lost")
    if bool(expected.get("no_send_now")) != bool(predicted.get("no_send_now")):
        errors.append("no_send_state")
    if bool(expected.get("unresolved_additional_send")) != bool(predicted.get("unresolved_additional_send")):
        errors.append("ambiguity_state")
    if expected.get("context_refs"):
        context = json.dumps(predicted.get("context_refs") or [], ensure_ascii=False).lower()
        if "memory/project_contacts.md" not in context:
            errors.append("context_reference_lost")
    return errors


def main() -> None:
    cases = {item["id"]: item for item in json.loads(CASES.read_text(encoding="utf-8"))["cases"]}
    predictions = json.loads(PREDICTIONS.read_text(encoding="utf-8"))["results"]
    totals: dict[str, Counter] = {}
    rows = []
    for item in predictions:
        expected = cases[item["case_id"]]["turns"][item["turn"] - 1]["reference"]
        errors = ["api_or_format_error"] if item.get("error") else assess(expected, item["predicted"])
        totals.setdefault(item["method"], Counter()).update(["turns"] + errors)
        rows.append({"method": item["method"], "case_id": item["case_id"], "turn": item["turn"], "errors": errors})
    print(json.dumps({"reference": "single-researcher exploratory draft, not independent gold",
                      "totals": {key: dict(value) for key, value in totals.items()},
                      "rows": rows}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
