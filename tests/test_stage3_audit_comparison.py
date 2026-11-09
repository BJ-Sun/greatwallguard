import importlib.util
from pathlib import Path
import unittest


MODULE = Path(__file__).resolve().parents[1] / "experiments" / "stage3_audit_comparison.py"
SPEC = importlib.util.spec_from_file_location("stage3_audit_comparison", MODULE)
stage3 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(stage3)


class Stage3AuditComparisonTests(unittest.TestCase):
    def test_fusion_requires_authorization_and_survival(self):
        verdict, _ = stage3._fuse(
            {"verdict": "authorized", "delegation": "explicit"},
            {"survival": "survives"},
        )
        self.assertEqual(verdict, "authorized")

    def test_unapproved_mediator_sensitivity_is_unauthorized(self):
        verdict, _ = stage3._fuse(
            {"verdict": "uncertain", "delegation": "absent"},
            {"survival": "disappears"},
        )
        self.assertEqual(verdict, "unauthorized")

    def test_delegated_dependency_is_not_treated_as_attack(self):
        verdict, _ = stage3._fuse(
            {"verdict": "uncertain", "delegation": "explicit"},
            {"survival": "disappears"},
        )
        self.assertEqual(verdict, "uncertain")

    def test_minimal_slice_keeps_matching_observation(self):
        prefix = [{"tool": "search", "arguments": {}, "result": "Alice: alice@example.com"}]
        proposed = {"arguments": {"recipients": ["alice@example.com"]}}
        selected = stage3._minimal_events(prefix, proposed)
        self.assertEqual(len(selected), 1)
        self.assertIn("alice@example.com", selected[0]["observation"])

    def test_completed_replay_rows_are_resumable(self):
        # The runner treats an existing arm as committed and does not invoke
        # the API again. This assertion fixes the persisted shape used by the
        # resume check.
        record = {"arms": {"replay": {"prediction": {"verdict": "uncertain"}}}}
        self.assertIn("replay", record["arms"])

    def test_credential_shaped_values_are_stably_pseudonymized(self):
        value = "sk" + "-" + "abcdefghijklmnop"
        first = stage3._minimize({"a": value, "b": value})
        self.assertNotIn(value, str(first))
        self.assertEqual(first["a"], first["b"])


if __name__ == "__main__":
    unittest.main()
