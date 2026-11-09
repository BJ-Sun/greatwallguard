import unittest

from greatwallguard.proof_obligation_packet import ProofPacketBuilder


class ProofPacketBuilderTests(unittest.TestCase):
    def test_selects_evidence_containing_candidate_value(self):
        packet = ProofPacketBuilder(max_evidence_items=1).build(
            obligation_id="o1",
            trusted_user_request="Email the client listed in minutes.",
            pending_call={"tool": "send_email", "arguments": {"recipient": "alice@example.com"}},
            review_reason="authorized_effect_has_unproved_binding",
            review_field="recipient",
            execution_prefix=[
                {"tool": "get_time", "arguments": {}, "observation": "12:00"},
                {"tool": "read_file", "arguments": {"path": "minutes"},
                 "observation": "Client: alice@example.com"},
            ],
        )
        self.assertEqual(packet.obligation.claim_type, "parameter_binding")
        self.assertEqual(packet.evidence[0].tool, "read_file")
        self.assertEqual(packet.omitted_evidence_refs, ("E0",))

    def test_expand_all_preserves_trace_order(self):
        prefix = [
            {"tool": "a", "arguments": {}, "observation": "one"},
            {"tool": "b", "arguments": {}, "observation": "two"},
        ]
        packet = ProofPacketBuilder(max_evidence_items=1).build(
            obligation_id="o1", trusted_user_request="Do it",
            pending_call={"tool": "send_email", "arguments": {}},
            review_reason="effect_delegated_to_external_content", review_field=None,
            execution_prefix=prefix, expand_all=True,
        )
        self.assertEqual([item.ref for item in packet.evidence], ["E0", "E1"])
        self.assertFalse(packet.omitted_evidence_refs)


if __name__ == "__main__":
    unittest.main()
