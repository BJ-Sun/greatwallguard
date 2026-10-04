import unittest

from email_decidability_audit import _ancestors


class EmailDecidabilityAuditTests(unittest.TestCase):
    def test_temporal_next_is_not_causal_evidence(self):
        edges = [
            {"source": "tool-observation", "target": "user-observation", "edge_type": "next"},
            {"source": "user-observation", "target": "send-action", "edge_type": "derived_from"},
        ]
        self.assertEqual({"user-observation"}, _ancestors("send-action", edges))

    def test_explicit_source_edge_is_causal_evidence(self):
        edges = [{"source": "tool-observation", "target": "send-action", "edge_type": "derived_from"}]
        self.assertEqual({"tool-observation"}, _ancestors("send-action", edges))


if __name__ == "__main__":
    unittest.main()
