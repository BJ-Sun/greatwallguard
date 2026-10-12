"""Regression checks for the request-only intent-delta diagnostic."""

import unittest

from evaluate import evaluate, load, scope_at_turn, validate


class IntentDeltaPilotTest(unittest.TestCase):
    def test_evidence_is_in_user_turn_only(self):
        cases, requests = load()
        validate(cases, requests)
        self.assertEqual(len(cases), 8)

    def test_temporal_step_constraint_does_not_forever_veto_send(self):
        cases, _ = load()
        for request_id in ("REQ-1acebe5568567731", "GWG-DEC-EMAIL-01", "GWG-DEC-EMAIL-02", "GWG-DEC-EMAIL-03"):
            with self.subTest(request_id=request_id):
                events = next(c["events"] for c in cases if c["request_id"] == request_id)
                self.assertEqual(len(scope_at_turn(events, 1)["constraints"]), 1)
                self.assertEqual(len(scope_at_turn(events, 2)["constraints"]), 0)
                self.assertTrue(any(e["effect"] == "send_email" for e in scope_at_turn(events, 2)["grants"]))

    def test_unresolved_continuation_never_becomes_grant(self):
        cases, _ = load()
        events = next(c["events"] for c in cases if c["request_id"] == "REQ-1acebe5568567731")
        later = scope_at_turn(events, 4)
        self.assertEqual(len(later["grants"]), 1)
        self.assertEqual(len(later["unresolved"]), 1)

    def test_existing_flat_extractor_has_known_gaps(self):
        result = evaluate()
        self.assertEqual(result["totals"]["cases"], 8)
        self.assertEqual(result["totals"]["baseline_tool_turn_missed"], 2)
        self.assertGreater(result["totals"]["slot_gaps"], 0)


if __name__ == "__main__":
    unittest.main()
