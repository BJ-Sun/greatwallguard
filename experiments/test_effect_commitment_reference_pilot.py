"""Offline checks for the request-only view and one-to-one matching."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from experiments.effect_commitment_reference_pilot import extract, match


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "experiments" / "effect_commitment_pilot"


class EffectCommitmentReferencePilotTest(unittest.TestCase):
    def test_blind_view_contains_no_outcome_or_trace(self) -> None:
        rows = [json.loads(x) for x in (BASE / "request_only.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 53)
        self.assertEqual(len({x["request_id"] for x in rows}), 53)
        for row in rows:
            self.assertEqual(set(row), {"request_id", "turns", "available_tools", "request_digest"})
            self.assertTrue(all(set(x) == {"turn", "user_message"} for x in row["turns"]))

    def test_draft_evidence_is_verbatim_and_temporal(self) -> None:
        requests = {x["request_id"]: x for x in map(json.loads, (BASE / "request_only.jsonl").read_text().splitlines())}
        draft = json.loads((BASE / "reference_draft.json").read_text())
        self.assertEqual(len(draft["cases"]), 10)
        for case in draft["cases"]:
            turns = {x["turn"]: x["user_message"] for x in requests[case["request_id"]]["turns"]}
            for item in case["commitments"] + case["unresolved"]:
                self.assertIn(item["evidence_span"], turns[item["turn"]])

    def test_two_explicit_grants_are_separate_atoms(self) -> None:
        request = next(x for x in map(json.loads, (BASE / "request_only.jsonl").read_text().splitlines())
                       if x["request_id"] == "REQ-39f88637bfb2ac34")
        candidate = extract(request)
        self.assertEqual([(x["operation"], x["destination"]) for x in candidate["commitments"]],
                         [("send_email", "owner@example.com"), ("send_email", "audit@example.com")])

    def test_future_grant_cannot_match_earlier_effect(self) -> None:
        annotation = {"request_id": "temporal", "commitments": [
            {"turn": 2, "operation": "send_email", "destination": "audit@example.com", "evidence_span": "later grant"}],
            "unresolved": []}
        graph = {"graph": {"levels": {"l0": {"graph": {"nodes": [
            {"id": "a", "node_type": "action", "turn": 1,
             "data": {"tool": "send_email", "parameters": {"recipients": ["audit@example.com"]}}},
            {"id": "e", "node_type": "effect", "turn": 1,
             "data": {"kind": "send", "persistent": True, "status": "succeeded"}},
        ], "edges": [{"source": "a", "target": "e", "edge_type": "causes"}]}}}}}
        self.assertEqual(match(annotation, graph)["outcomes"][0]["verdict"], "outside_explicit_scope")


if __name__ == "__main__":
    unittest.main()
