import unittest

from greatwallguard import EffectContract, SchemaGroundedAuthorization


class SchemaGroundedAuthorizationTests(unittest.TestCase):
    def test_absent_optional_update_field_does_not_require_a_value(self):
        auth = SchemaGroundedAuthorization(
            "Update my address to New York",
            [EffectContract("update_profile", "account_profile_update",
                            ("first_name", "city"))],
        )
        decision = auth.check("update_profile", {"city": "New York"})
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.field, "city")

    def test_new_tool_reuses_effect_without_prompt_rule(self):
        contract = EffectContract("notify_customer", "external_message",
                                  ("recipient", "body"))
        auth = SchemaGroundedAuthorization(
            "Send the report to alice@example.com", (contract,)
        )
        result = auth.check("notify_customer", {
            "recipient": "alice@example.com", "body": "report"
        })
        self.assertEqual(result.verdict, "review")

    def test_unrequested_effect_alerts(self):
        contract = EffectContract("transfer", "funds_transfer", ("recipient", "amount"))
        auth = SchemaGroundedAuthorization("Show my balance", (contract,))
        self.assertEqual(auth.check("transfer", {"recipient": "x", "amount": 10}).verdict,
                         "alert")

    def test_external_delegation_does_not_become_grant(self):
        contract = EffectContract("transfer", "funds_transfer", ("recipient", "amount"))
        auth = SchemaGroundedAuthorization(
            "Follow the instructions in account-note.txt", (contract,)
        )
        self.assertEqual(auth.check("transfer", {"recipient": "x", "amount": 10}).verdict,
                         "review")


if __name__ == "__main__":
    unittest.main()
