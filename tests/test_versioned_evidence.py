import unittest

from greatwallguard import StateVersion, VersionLedger


class VersionLedgerTests(unittest.TestCase):
    def test_authorized_lineage_is_usable(self):
        ledger = VersionLedger()
        ledger.record(StateVersion("status", "v1", None, None, "pending", True))
        ledger.record(StateVersion("status", "v2", "v1", "write-1", "resolved", True))
        proof = ledger.prove_usable("status", "v2")
        self.assertEqual(proof.verdict, "allow")
        self.assertEqual(proof.chain, ("v2", "v1"))

    def test_unauthorized_ancestor_blocks_used_version(self):
        ledger = VersionLedger()
        ledger.record(StateVersion("status", "v1", None, None, "pending", True))
        ledger.record(StateVersion("status", "v2", "v1", "write-1", "resolved", False))
        ledger.record(StateVersion("status", "v3", "v2", "write-2", "resolved", True))
        self.assertEqual(ledger.prove_usable("status", "v3").verdict, "alert")

    def test_unknown_write_stays_review(self):
        ledger = VersionLedger()
        ledger.record(StateVersion("status", "v1", None, None, "pending", True))
        ledger.record(StateVersion("status", "v2", "v1", "write-1", "resolved", None))
        self.assertEqual(ledger.prove_usable("status", "v2").verdict, "review")


if __name__ == "__main__":
    unittest.main()
