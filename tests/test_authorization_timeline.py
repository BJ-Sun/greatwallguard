import unittest

from greatwallguard import (
    AuthorizationDAG,
    AuthorizationDAGCompiler,
    AuthorizationRuntime,
    AuthorizationTimeline,
    EffectContract,
)


CONTRACTS = (
    EffectContract(
        "send_email", "external_message", ("recipients",),
        required_fields=("recipients",),
    ),
)


class AuthorizationTimelineTests(unittest.TestCase):
    def test_future_turn_cannot_authorize_earlier_call(self):
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        before = runtime.authorize_tool_call(
            "before", "send_email", {"recipients": ["alice@example.com"]},
        )
        self.assertEqual(before.verdict, "alert")

        delta = AuthorizationDAGCompiler(CONTRACTS).compile(
            "Send an email to alice@example.com"
        )
        timeline.apply(turn=2, trusted_message="Send an email to alice@example.com",
                       delta=delta)
        after = runtime.authorize_tool_call(
            "after", "send_email", {"recipients": ["alice@example.com"]},
        )
        self.assertEqual(after.verdict, "allow")

    def test_each_turn_has_independent_budget(self):
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        for turn in (1, 2):
            message = "Send an email to alice@example.com"
            timeline.apply(
                turn=turn, trusted_message=message,
                delta=AuthorizationDAGCompiler(CONTRACTS).compile(message),
            )
            decision = runtime.authorize_tool_call(
                f"c{turn}", "send_email", {"recipients": ["alice@example.com"]},
            )
            self.assertEqual(decision.verdict, "allow")
            runtime.commit_tool_result(f"c{turn}", succeeded=True)
        self.assertEqual(len(timeline.records), 2)
        self.assertNotEqual(
            timeline.records[0].added_effect_ids,
            timeline.records[1].added_effect_ids,
        )

    def test_explicit_revoke_disables_old_effect(self):
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        delta = AuthorizationDAGCompiler(CONTRACTS).compile(
            "Send an email to alice@example.com"
        )
        first = timeline.apply(
            turn=1, trusted_message="Send an email to alice@example.com", delta=delta,
        )
        timeline.apply(
            turn=2, trusted_message="Cancel that authorization",
            delta=AuthorizationDAG(), revoke_effect_ids=first.added_effect_ids,
        )
        decision = runtime.authorize_tool_call(
            "c", "send_email", {"recipients": ["alice@example.com"]},
        )
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(decision.reason, "authorization_revoked")


if __name__ == "__main__":
    unittest.main()
