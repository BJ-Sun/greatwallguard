import unittest

from greatwallguard import EffectType, TaskScope
from greatwallguard.agentlab_recorder import AgentLabGraphRecorder


class AgentLabGraphRecorderTests(unittest.TestCase):
    def setUp(self):
        self.recorder = AgentLabGraphRecorder(
            TaskScope("recorder", "capture a trace", frozenset(EffectType))
        )

    def test_qualified_file_target_is_not_double_prefixed(self):
        effect = self.recorder.infer_effect(
            "create_file", {"path": "file://workspace/report.md"}
        )
        self.assertEqual(effect.target, "file://workspace/report.md")

    def test_memory_uri_is_preserved(self):
        effect = self.recorder.infer_effect(
            "write_memory", {"path": "memory://daily/current"}
        )
        self.assertEqual(effect.target, "memory://daily/current")

    def test_memory_md_is_a_workspace_file_target(self):
        effect = self.recorder.infer_effect(
            "write_file", {"path": "MEMORY.md"}
        )
        self.assertEqual(effect.target, "file://workspace/MEMORY.md")

    def test_email_getter_is_read_not_send(self):
        effect = self.recorder.infer_effect("get_sent_emails", {})
        self.assertIs(effect.kind, EffectType.READ)

    def test_send_email_is_external_send(self):
        effect = self.recorder.infer_effect(
            "send_email", {"to": "alice@example.com"}
        )
        self.assertIs(effect.kind, EffectType.SEND)

    def test_orphan_return_is_recorded_without_raising(self):
        env = object()
        node_id = self.recorder.after_tool_call(
            env, "custom_tool", "bridge returned", success=True
        )
        node = self.recorder.graph.node(node_id)
        self.assertEqual(node.data["source"], "tool_return")
        self.assertTrue(self.recorder.runtime.trace.events[-1].data["orphan"])

    def test_malformed_arguments_do_not_break_passive_capture(self):
        env = object()
        action_id = self.recorder.before_tool_call(env, "custom_tool", ["not", "an", "object"])
        self.assertEqual(self.recorder.graph.node(action_id).data["tool"], "custom_tool")

    def test_state_read_edge_has_trace_event(self):
        env = object()
        self.recorder.begin_session(env, "maintain memory")
        self.recorder.before_tool_call(env, "write_memory", {"path": "memory://x"})
        self.recorder.after_tool_call(env, "write_memory", "written")
        self.recorder.before_tool_call(env, "read_memory", {"path": "memory://x"})
        self.recorder.after_tool_call(env, "read_memory", "written")
        reads = [
            event for event in self.recorder.runtime.trace.events
            if event.event_type.value == "state_read"
        ]
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0].data["object_id"], "memory://x")

    def test_background_effect_keeps_latest_environment_source(self):
        class Env:
            workspace = object()

        env = Env()
        self.recorder.begin_session(env, "write a note")
        self.recorder.before_tool_call(env, "write_memory", {"path": "memory://x"})
        return_node = self.recorder.after_tool_call(env, "write_memory", "written")
        self.recorder.background_effect(
            env.workspace,
            operation="memory_flush",
            target="memory://daily/today",
        )
        effects = [
            node for node in self.recorder.graph.nodes.values()
            if node.node_type.value == "effect" and node.data["operation"] == "memory_flush"
        ]
        self.assertEqual(effects[0].data["source_node_ids"], [return_node])

    def test_context_load_records_memory_state_read(self):
        from types import SimpleNamespace

        workspace = SimpleNamespace(
            files={"MEMORY.md": SimpleNamespace(exists=True, content="saved note")}
        )
        env = SimpleNamespace(workspace=workspace)
        self.recorder.begin_session(env, "maintain memory")
        self.recorder.background_effect(
            workspace,
            operation="dreaming",
            target="file://workspace/MEMORY.md",
        )
        self.recorder.record_context_load(env, workspace)
        reads = [
            event for event in self.recorder.runtime.trace.events
            if event.event_type.value == "state_read"
        ]
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0].data["object_id"], "file://workspace/MEMORY.md")

    def test_write_return_is_not_a_state_read(self):
        env = object()
        self.recorder.begin_session(env, "maintain a file")
        self.recorder.before_tool_call(env, "write_file", {"path": "report.md"})
        self.recorder.after_tool_call(env, "write_file", "saved")
        self.recorder.before_tool_call(env, "write_file", {"path": "report.md"})
        self.recorder.after_tool_call(env, "write_file", "saved again")
        reads = [
            event for event in self.recorder.runtime.trace.events
            if event.event_type.value == "state_read"
        ]
        self.assertEqual(reads, [])


if __name__ == "__main__":
    unittest.main()
