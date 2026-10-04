import unittest

from online_effect_guard import OnlineEffectGuard


class OnlineEffectGuardTests(unittest.TestCase):
    def test_explicit_grant_is_consumed_only_after_success(self):
        guard = OnlineEffectGuard()
        guard.on_user_message("Send an email to owner@example.com with subject 'Routine status' and body 'Done'.", turn=1, trusted=True)
        args = {"recipients": ["owner@example.com"], "subject": "Routine status", "body": "Done"}
        first = guard.before_tool_call("send_email", args, turn=1, call_id="a")
        self.assertEqual("allow", first.verdict)
        guard.after_tool_result("a", succeeded=False)
        retry = guard.before_tool_call("send_email", args, turn=1, call_id="b")
        self.assertEqual("allow", retry.verdict)
        guard.after_tool_result("b", succeeded=True)
        extra = guard.before_tool_call("send_email", args, turn=1, call_id="c")
        self.assertEqual("alert", extra.verdict)

    def test_parameter_difference_is_soft_alert_and_marked_possible_fp(self):
        guard = OnlineEffectGuard()
        guard.on_user_message("Send an email to owner@example.com with subject 'Routine status'.", turn=1, trusted=True)
        result = guard.before_tool_call("send_email", {"recipients": ["other@example.com"], "subject": "Routine status"},
                                        turn=1, call_id="a")
        self.assertEqual("review", result.verdict)
        self.assertTrue(result.possible_false_positive)

    def test_untrusted_text_cannot_grant_authority(self):
        guard = OnlineEffectGuard()
        guard.on_user_message("Send an email to owner@example.com with subject 'Routine status'.", turn=1, trusted=False)
        result = guard.before_tool_call("send_email", {"recipients": ["owner@example.com"], "subject": "Routine status"},
                                        turn=1, call_id="a")
        self.assertEqual("alert", result.verdict)

    def test_unbound_body_needs_review(self):
        guard = OnlineEffectGuard()
        guard.on_user_message("Send an email to owner@example.com with subject 'Routine status'.", turn=1, trusted=True)
        result = guard.before_tool_call("send_email", {"recipients": ["owner@example.com"],
                                                      "subject": "Routine status", "body": "Unexpected"},
                                        turn=1, call_id="a")
        self.assertEqual("review", result.verdict)
        self.assertTrue(result.possible_false_positive)

    def test_unknown_tool_review(self):
        guard = OnlineEffectGuard()
        result = guard.before_tool_call("mock_exec", {"command": "echo hello"}, turn=1, call_id="a")
        self.assertEqual("review", result.verdict)
        self.assertTrue(result.possible_false_positive)

    def test_future_user_message_cannot_authorize_past_call(self):
        guard = OnlineEffectGuard()
        guard.on_user_message("Send an email to owner@example.com with subject 'Routine status' and body 'Done'.",
                              turn=3, trusted=True)
        result = guard.before_tool_call("send_email", {"recipients": ["owner@example.com"],
                                                      "subject": "Routine status", "body": "Done"},
                                        turn=2, call_id="a")
        self.assertEqual("alert", result.verdict)


if __name__ == "__main__":
    unittest.main()
