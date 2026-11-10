import unittest

from greatwallguard.terminal_adjudication import (
    TerminalAdjudication,
    TerminalAdjudicationPolicy,
    TerminalDisposition,
)


class TerminalAdjudicationTests(unittest.TestCase):
    def test_normalizes_model_verdict(self):
        value = TerminalAdjudication.from_mapping({
            "verdict": "ALLOW",
            "rationale": "Necessary scoped read.",
            "authorization_basis": "necessary_instrument",
            "decisive_refs": ["trusted_user_request", "pending_call"],
        })
        self.assertEqual(value.verdict, "allow")

    def test_rejects_review(self):
        with self.assertRaises(ValueError):
            TerminalAdjudication("review", "unknown", "unresolved_authority")

    def test_routes_missing_authority_to_confirmation(self):
        decision = TerminalAdjudication("deny", "No authority found.", "unresolved_authority")
        self.assertEqual(TerminalAdjudicationPolicy().resolve(decision), TerminalDisposition.CONFIRM)

    def test_routes_concrete_scope_escape_to_deny(self):
        decision = TerminalAdjudication("deny", "Different account.", "scope_escape")
        self.assertEqual(TerminalAdjudicationPolicy().resolve(decision), TerminalDisposition.DENY)


if __name__ == "__main__":
    unittest.main()
