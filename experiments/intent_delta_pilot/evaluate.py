#!/usr/bin/env python3
"""Request-only diagnostic of an exploratory, assistant-authored intent-delta draft.

No attack labels, execution traces, tool results, or outcome oracles enter the
extractor. The three local controls are projected to user turns at load time.
The draft is not independent ground truth and scores are not detection metrics.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments"))
from effect_commitment_reference_pilot import extract  # noqa: E402

HERE = Path(__file__).resolve().parent
REQUESTS = ROOT / "experiments" / "effect_commitment_pilot" / "request_only.jsonl"
LOCAL = ROOT / "dataset" / "benign-controls" / "raw-runs"
EFFECTS = {"send_email", "share_file", "create_calendar_event"}
KINDS = {"grant", "constraint", "unresolved"}
SLOT_KINDS = {"literal", "reference", "task_data"}


def _read_request_only() -> dict[str, dict[str, Any]]:
    requests = {}
    for line in REQUESTS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            requests[row["request_id"]] = {"request_id": row["request_id"], "turns": row["turns"]}
    return requests


def _local_user_view(request_id: str) -> dict[str, Any]:
    case_path = LOCAL / request_id / "cases" / f"{request_id}.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    # Explicit projection boundary: no other case field is passed to extraction.
    turns = [{"turn": int(row["turn"]), "user_message": row["user_message"]}
             for row in case["execution"]["visible_agent_turns"]]
    return {"request_id": request_id, "turns": turns}


def load() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    draft = json.loads((HERE / "reference_draft.json").read_text(encoding="utf-8"))
    requests = _read_request_only()
    for case in draft["cases"]:
        if case["source"] == "local_control":
            requests[case["request_id"]] = _local_user_view(case["request_id"])
        elif case["source"] != "request_only":
            raise ValueError(f"unknown source: {case['source']}")
    return draft["cases"], requests


def validate(cases: list[dict[str, Any]], requests: dict[str, dict[str, Any]]) -> None:
    seen = set()
    for case in cases:
        request_id = case["request_id"]
        if request_id in seen or request_id not in requests:
            raise ValueError(f"duplicate or absent request: {request_id}")
        seen.add(request_id)
        turns = {row["turn"]: row["user_message"] for row in requests[request_id]["turns"]}
        for event in case["events"]:
            if event["kind"] not in KINDS or event["effect"] not in EFFECTS:
                raise ValueError(f"invalid kind/effect in {request_id}")
            if event["turn"] not in turns or not event["evidence"] or event["evidence"] not in turns[event["turn"]]:
                raise ValueError(f"missing exact user evidence in {request_id}, turn {event['turn']}: {event['evidence']!r}")
            if event["kind"] == "constraint":
                if event.get("validity") != "this_step":
                    raise ValueError("pilot only supports step-local constraints")
            elif event["kind"] == "grant":
                for slot in event["slots"].values():
                    if slot["kind"] not in SLOT_KINDS:
                        raise ValueError(f"unknown slot kind in {request_id}")
                    if slot["kind"] == "reference" and not slot.get("resolves_to"):
                        raise ValueError(f"unresolved reference in {request_id}")
                    if slot["kind"] == "task_data" and not slot.get("selector"):
                        raise ValueError(f"task_data without selector in {request_id}")


def scope_at_turn(events: list[dict[str, Any]], turn: int) -> dict[str, list[dict[str, Any]]]:
    """A tiny state reducer; only request evidence can grant authority.

    Grants remain available; a step-local constraint only applies to its own
    turn. No revoke/amend semantics are claimed or tested in this pilot.
    """
    return {
        "grants": [e for e in events if e["kind"] == "grant" and e["turn"] <= turn],
        "constraints": [e for e in events if e["kind"] == "constraint" and e["turn"] == turn],
        "unresolved": [e for e in events if e["kind"] == "unresolved" and e["turn"] <= turn],
    }


def evaluate() -> dict[str, Any]:
    cases, requests = load()
    validate(cases, requests)
    totals = Counter()
    rows = []
    for case in cases:
        request_id = case["request_id"]
        candidate = extract(requests[request_id])
        expected = [e for e in case["events"] if e["kind"] == "grant"]
        got = [e for e in candidate["commitments"] if e["operation"] in EFFECTS]
        matched = set()
        missed = []
        slot_gaps = []
        for event in expected:
            choices = [i for i, item in enumerate(got) if i not in matched
                       and item["turn"] == event["turn"] and item["operation"] == event["effect"]]
            # For two same-operation grants in one turn, prefer exact recipient.
            recipient = event["slots"].get("recipient", {})
            expected_address = recipient.get("value") if recipient.get("kind") == "literal" else recipient.get("resolves_to")
            if expected_address:
                exact = [i for i in choices if got[i].get("destination") == expected_address.lower()]
                if exact:
                    choices = exact
            if not choices:
                missed.append(f"t{event['turn']}:{event['effect']}")
                continue
            idx = choices[0]
            matched.add(idx)
            item = got[idx]
            for name, slot in event["slots"].items():
                actual_name = {"recipient": "destination", "file_id": "object_id", "event": "object_name"}.get(name, name)
                if slot["kind"] == "task_data":
                    # The existing flat extractor cannot encode a selector,
                    # even if it emits a same-tool commitment.
                    slot_gaps.append(f"t{event['turn']}:{name}:task_data_not_represented")
                elif actual_name in ("destination", "object_id", "subject", "permission", "object_name"):
                    target = slot.get("resolves_to", slot.get("value"))
                    if str(item.get(actual_name, "")).lower() != str(target).lower():
                        slot_gaps.append(f"t{event['turn']}:{name}:value_mismatch")
                elif name == "body":
                    slot_gaps.append(f"t{event['turn']}:body:not_represented")
        extras = [f"t{e['turn']}:{e['operation']}" for i, e in enumerate(got) if i not in matched]
        counts = Counter(e["kind"] for e in case["events"])
        totals.update({"cases": 1, "draft_grants": len(expected), "baseline_tool_turn_matched": len(matched),
                       "baseline_tool_turn_missed": len(missed), "baseline_tool_turn_extra": len(extras),
                       "draft_constraints": counts["constraint"], "draft_unresolved": counts["unresolved"],
                       "slot_gaps": len(slot_gaps)})
        rows.append({"request_id": request_id, "draft_grants": len(expected), "baseline_matched": len(matched),
                     "missed": missed, "extra": extras, "slot_gaps": slot_gaps,
                     "draft_constraints": counts["constraint"], "draft_unresolved": counts["unresolved"]})
    return {"provenance": "assistant-authored exploratory draft; not independent accuracy or attack-detection evaluation",
            "totals": dict(totals), "cases": rows}


if __name__ == "__main__":
    print(json.dumps(evaluate(), ensure_ascii=False, indent=2))
