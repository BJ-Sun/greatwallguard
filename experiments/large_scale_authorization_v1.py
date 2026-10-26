#!/usr/bin/env python3
"""Full 570-case replay after completing the finite programmatic contracts."""

from __future__ import annotations

import json
from collections import Counter, defaultdict

from large_scale_authorization_v0 import ROOT, records, target_match
from programmatic_effect_guard_v1 import ProgrammaticEffectGuardV1


OUT = ROOT / "experiments/large_scale_authorization_v1_results.json"


def replay(case: dict) -> list[dict]:
    guard = ProgrammaticEffectGuardV1()
    messages = defaultdict(list)
    for row in case.get("execution", {}).get("visible_agent_turns", []):
        if row.get("user_message"):
            messages[int(row["turn"])].append(str(row["user_message"]))
    calls = sorted(case.get("execution", {}).get("tool_call_trace", []),
                   key=lambda row: (int(row.get("turn") or 0), int(row.get("order") or 0)))
    turns, next_turn, decisions = sorted(messages), 0, []
    for sequence, call in enumerate(calls):
        turn = int(call.get("turn") or 0)
        while next_turn < len(turns) and turns[next_turn] <= turn:
            for message in messages[turns[next_turn]]:
                guard.on_user_message(message, turn=turns[next_turn], trusted=True)
            next_turn += 1
        call_id = f"call-{sequence}"
        args = call.get("arguments") or {}
        decision = guard.before_tool_call(str(call["tool"]), args, turn=turn, call_id=call_id)
        if call_id in guard.pending or call_id in guard.extended_pending:
            guard.after_tool_result(call_id, succeeded=not bool(call.get("error"))
                                    and not bool(call.get("shadow_blocked")))
        decisions.append({"turn": turn, "tool": call["tool"], "arguments": args,
                          "verdict": decision.verdict, "reason": decision.reason,
                          "possible_false_positive": decision.possible_false_positive})
    return decisions


def main() -> dict:
    if OUT.exists():
        raise FileExistsError(f"Frozen result exists: {OUT}")
    results, failures = [], []
    for meta in records():
        try:
            case = json.loads(meta["path"].read_text(encoding="utf-8"))
            decisions = replay(case)
            targets = [d for d in decisions if target_match(case, d)] if meta["group"] == "attack_positive" else []
            results.append({"case_id": meta["case_id"], "group": meta["group"], "tier": meta["tier"],
                            "target": meta["target"], "path": str(meta["path"].relative_to(ROOT.parent)),
                            "calls": len(decisions), "review_calls": sum(d["verdict"] == "review" for d in decisions),
                            "alert_calls": sum(d["verdict"] == "alert" for d in decisions),
                            "target_call_count": len(targets),
                            "target_verdicts": [d["verdict"] for d in targets],
                            "decisions": [{"turn": d["turn"], "tool": d["tool"], "verdict": d["verdict"],
                                           "reason": d["reason"], "target_call": d in targets}
                                          for d in decisions]})
        except Exception as error:
            failures.append({"case_id": meta["case_id"], "error": f"{type(error).__name__}: {error}"[:240]})
    reasons = Counter(d["reason"] for row in results for d in row["decisions"] if d["verdict"] != "allow")
    output = {"schema": "gwg-large-scale-authorization-v1",
              "protocol": "frozen_trace_pre_call_replay",
              "detector": "ProgrammaticEffectGuardV1 finite effect contracts",
              "failures": failures, "nonallow_reasons": dict(reasons), "rows": results}
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(results), "failures": len(failures),
                      "nonallow_reasons": output["nonallow_reasons"]}, ensure_ascii=False, indent=2))
    return output


if __name__ == "__main__":
    main()
