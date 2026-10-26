import json
import unittest

from greatwallguard import ProgrammaticAuthorizationGuard


class ProgrammaticGuardTests(unittest.TestCase):
    def test_public_runtime_lifecycle_and_single_use(self) -> None:
        guard = ProgrammaticAuthorizationGuard()
        guard.on_user_message(
            "Send to alice@example.com with subject 'Status' body 'Done'.", turn=1
        )
        decision = guard.before_tool_call(
            "send_email",
            {"recipients": ["alice@example.com"], "subject": "Status", "body": "Done"},
            turn=1,
            call_id="c1",
        )
        self.assertEqual(decision.verdict, "allow")
        guard.after_tool_result("c1", succeeded=True)
        second = guard.before_tool_call(
            "send_email",
            {"recipients": ["alice@example.com"], "subject": "Status", "body": "Done"},
            turn=1,
            call_id="c2",
        )
        self.assertEqual((second.verdict, second.reason),
                         ("alert", "no_matching_user_commitment"))

    def test_unknown_tool_fails_to_review(self) -> None:
        guard = ProgrammaticAuthorizationGuard()
        decision = guard.before_tool_call("new_tool", {}, turn=1, call_id="c1")
        self.assertEqual((decision.verdict, decision.reason),
                         ("review", "unmapped_tool_effect"))

    def test_untrusted_message_cannot_grant_authority(self) -> None:
        guard = ProgrammaticAuthorizationGuard()
        guard.on_user_message(
            "Send to alice@example.com with subject 'Status' body 'Done'.",
            turn=1,
            trusted=False,
        )
        decision = guard.before_tool_call(
            "send_email",
            {"recipients": ["alice@example.com"], "subject": "Status", "body": "Done"},
            turn=1,
            call_id="c1",
        )
        self.assertEqual(decision.verdict, "alert")

    def test_state_round_trip_is_json_serializable_and_behavior_preserving(self) -> None:
        original = ProgrammaticAuthorizationGuard()
        original.on_user_message(
            "Inventory portal.internal and verify its HTTPS service.", turn=1
        )
        state = json.loads(json.dumps(original.export_state()))
        restored = ProgrammaticAuthorizationGuard.from_state(state)
        expected = original.before_tool_call(
            "mock_network_scan", {"target": "portal.internal", "ports": [443]},
            turn=1, call_id="original",
        )
        actual = restored.before_tool_call(
            "mock_network_scan", {"target": "portal.internal", "ports": [443]},
            turn=1, call_id="restored",
        )
        self.assertEqual(actual, expected)

    def test_state_schema_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported"):
            ProgrammaticAuthorizationGuard.from_state({"schema": "future"})


if __name__ == "__main__":
    unittest.main()
