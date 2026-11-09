import unittest

from greatwallguard import SymbolicTaskScope


class SymbolicScopeCodecTests(unittest.TestCase):
    def test_from_dict_validates_model_output(self):
        scope = SymbolicTaskScope.from_dict({
            "scope_id": "delete-largest",
            "grants": [{
                "grant_id": "delete-one", "effect": "delete_file", "budget": 1,
                "bindings": {"file_id": {
                    "op": "project", "field": "id_",
                    "source": {"op": "argmax", "field": "size",
                               "source": {"op": "tool_result", "tool": "list_files"}},
                }},
            }],
        }, evidence="Delete the largest file")
        self.assertEqual(scope.grants[0].effect, "delete_file")

    def test_from_dict_rejects_unexecutable_operator(self):
        with self.assertRaises(ValueError):
            SymbolicTaskScope.from_dict({
                "scope_id": "bad", "grants": [{
                    "grant_id": "bad", "effect": "delete_file",
                    "bindings": {"file_id": {"op": "guess", "value": "11"}},
                }],
            }, evidence="bad")


if __name__ == "__main__":
    unittest.main()
