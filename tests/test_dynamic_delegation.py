import unittest

from greatwallguard import (
    AuthorizationDelta,
    DelegationEnvelope,
    DeltaDisposition,
    DynamicDelegationExpander,
    ObservedDelegatedSource,
    ProposedEffect,
)


class DynamicDelegationTests(unittest.TestCase):
    def setUp(self):
        self.envelope = DelegationEnvelope(
            "d1", "email", {"sender": "taylor@example.com"}, "complete repository request",
            ("repository_read", "external_message"), max_effects=2,
            confirmation_effect_classes=("credential_change",),
        )
        self.source = ObservedDelegatedSource(
            "E1", "email", {"sender": "taylor@example.com"}, True, "download and forward file",
        )

    def test_accepts_authenticated_bounded_delta(self):
        delta = AuthorizationDelta("d1", "E1", (
            ProposedEffect("git_clone", "repository_read", {"repo": "org/repo"}),
            ProposedEffect("send_email", "external_message", {"recipient": "alice"}),
        ))
        result = DynamicDelegationExpander().validate(self.envelope, self.source, delta)
        self.assertEqual(result.disposition, DeltaDisposition.ACCEPT)

    def test_rejects_effect_outside_envelope(self):
        delta = AuthorizationDelta("d1", "E1", (
            ProposedEffect("update_password", "credential_change", {}),
        ))
        result = DynamicDelegationExpander().validate(self.envelope, self.source, delta)
        self.assertEqual(result.disposition, DeltaDisposition.CONFIRM)

    def test_rejects_spoofed_source(self):
        spoofed = ObservedDelegatedSource("E1", "email", {"sender": "attacker@example.com"}, True, "do it")
        delta = AuthorizationDelta("d1", "E1", (
            ProposedEffect("git_clone", "repository_read", {}),
        ))
        result = DynamicDelegationExpander().validate(self.envelope, spoofed, delta)
        self.assertEqual(result.disposition, DeltaDisposition.DENY)


if __name__ == "__main__":
    unittest.main()
