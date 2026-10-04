#!/usr/bin/env python3
"""Freeze a request-only annotation view before effect/trace analysis.

The view hides attack labels, graph outcomes, trace and case paths. A separate
mapping exists solely for joining annotations back to outcomes after freeze.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTACK_REPO = ROOT.parent / "openclaw-longrange-manual-lab"
OUT = ROOT / "experiments" / "effect_commitment_pilot"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def freeze() -> dict[str, int]:
    pairs = read_jsonl(ROOT / "experiments" / "effect_scope_pilot" / "pairs.jsonl")
    selected = []
    for pair in pairs:
        selected.extend([
            {"source_path": ROOT / pair["control_case_path"], "label": "normal", "stratum": "matched"},
            {"source_path": ATTACK_REPO / pair["attack_case_path"], "label": "attack", "stratum": "matched"},
        ])
    for row in read_jsonl(ROOT / "dataset" / "benign-controls" / "stress-cases" / "index.jsonl"):
        selected.append({"source_path": ROOT / row["case_path"], "label": "normal", "stratum": "stress"})

    blind = []
    mapping = []
    for item in selected:
        case = json.loads(item["source_path"].read_text(encoding="utf-8"))
        turns = [{"turn": int(row.get("turn", index)), "user_message": str(row.get("user_message", ""))}
                 for index, row in enumerate((case.get("execution") or {}).get("visible_agent_turns") or [], start=1)]
        if not turns or not all(row["user_message"] for row in turns):
            raise ValueError(f"missing visible user request: {item['source_path']}")
        tools = sorted({str(x.get("canonical_name") or x.get("name"))
                        for x in (case.get("tool_contract") or {}).get("tools") or []})
        request_id = "REQ-" + digest({"turns": turns, "tools": tools})[:16]
        blind.append({"request_id": request_id, "turns": turns, "available_tools": tools,
                      "request_digest": digest(turns)})
        mapping.append({"request_id": request_id, "source_case_id": case.get("case_id"),
                        "source_path": str(item["source_path"].relative_to(
                            ROOT if item["source_path"].is_relative_to(ROOT) else ATTACK_REPO)),
                        "source_repository": "greatwallguard" if item["source_path"].is_relative_to(ROOT) else "attack_repo",
                        "label": item["label"], "stratum": item["stratum"]})
    if len({row["request_id"] for row in blind}) != len(blind):
        raise ValueError("duplicate request sequence; inspect before annotation")
    blind.sort(key=lambda row: row["request_id"])
    mapping.sort(key=lambda row: row["request_id"])
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "request_only.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in blind), encoding="utf-8")
    (OUT / "evaluation_mapping.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in mapping), encoding="utf-8")
    return {"cases": len(blind), "user_messages": sum(len(row["turns"]) for row in blind),
            "distinct_user_messages": len({turn["user_message"] for row in blind for turn in row["turns"]})}


if __name__ == "__main__":
    print(json.dumps(freeze()))
