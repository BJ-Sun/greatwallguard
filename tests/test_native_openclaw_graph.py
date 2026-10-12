"""Completeness and provenance-label tests for native OpenClaw recording."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from greatwallguard.native_openclaw_graph import NativeOpenClawGraph, read_native_events
from greatwallguard.model import EdgeType, NodeType


def event(role, content=None, **kwargs):
    return {"type": "message", "message": {"role": role, "content": content, **kwargs}}


def call(call_id, name, args):
    return {"type": "toolCall", "id": call_id, "name": name, "arguments": args}


class NativeOpenClawGraphTests(unittest.TestCase):
    def test_read_only_reader_includes_retained_wal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.sqlite"
            writer = sqlite3.connect(path)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE transcript_events(seq INTEGER PRIMARY KEY, event_json TEXT)")
                writer.execute("INSERT INTO transcript_events VALUES (?, ?)",
                               (1, json.dumps(event("user", "hello"))))
                writer.commit()
                self.assertGreater(Path(str(path) + "-wal").stat().st_size, 0)
                self.assertEqual(read_native_events(path)[0][1]["message"]["content"], "hello")
            finally:
                writer.close()

    def test_call_result_write_read_send_and_candidate_fields(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Send an update to owner@example.com."))
        graph.ingest(2, event("assistant", [call("w", "write", {"path": "MEMORY.md",
                                                             "content": "Owner: owner@example.com"})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "ok"}], toolCallId="w"))
        graph.ingest_workspace_snapshot({"turn": 1, "op": "create", "path": "MEMORY.md",
                                         "before_sha256": None,
                                         "after_sha256": hashlib.sha256(b"Owner: owner@example.com").hexdigest(),
                                         "version": 1})
        graph.ingest(4, event("assistant", [call("r", "read", {"path": "MEMORY.md"})]))
        graph.ingest(5, event("toolResult", [{"type": "text", "text": "Owner: owner@example.com"}], toolCallId="r"))
        graph.ingest(6, event("assistant", [call("s", "agentdojo__send_email", {
            "recipients": ["owner@example.com"], "subject": "Update", "body": "Done"})]))
        graph.ingest(7, event("toolResult", [{"type": "text", "text": "sent"}], toolCallId="s"))
        report = graph.coverage()
        self.assertEqual(report["native_events_with_audit_anchor"], report["native_events"])
        self.assertEqual(report["tool_calls"], 3)
        self.assertEqual(report["paired_tool_results"], 3)
        self.assertEqual(report["file_writes"], 1)
        self.assertEqual(report["snapshot_bound_native_writes"], 1)
        self.assertFalse(report["unknown_effect_calls"])
        self.assertTrue(any(edge.edge_type is EdgeType.RETURNS for edge in graph.graph.edges))
        self.assertTrue(any(edge.edge_type is EdgeType.READS for edge in graph.graph.edges))
        self.assertTrue(any(edge.edge_type is EdgeType.PARAMETER_CANDIDATE and
                            edge.evidence["parameter_field"].startswith("recipients")
                            for edge in graph.graph.edges))
        self.assertTrue(any(node.node_type is NodeType.STATE and node.data.get("fingerprint")
                            for node in graph.graph.nodes.values()))
        send = graph.graph.node(graph.calls["s"]["action_id"])
        self.assertEqual(send.data["parameter_source_summary"]["recipients[0]"]["status"],
                         "candidate_only_not_causal")
        self.assertEqual(send.data["parameter_source_summary"]["body"]["status"],
                         "no_exact_prior_match")
        graph.assert_complete_process()

    def test_orphan_result_is_retained_and_fails_completeness(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("toolResult", [{"type": "text", "text": "missing tool"}],
                              toolCallId="absent", toolName="search", isError=True))
        self.assertEqual(graph.coverage()["tool_result_events"], 1)
        self.assertEqual(graph.coverage()["native_events_with_audit_anchor"], 1)
        self.assertEqual(graph.coverage()["paired_tool_results"], 0)
        self.assertTrue(any(node.data.get("coverage_gap") == "missing_call_unclassified"
                            for node in graph.graph.nodes.values()))
        with self.assertRaises(ValueError):
            graph.assert_complete_process()
        with self.assertRaises(ValueError):
            graph.assert_known_tool_dispatch_coverage()

    def test_tool_not_found_orphan_keeps_transcript_gap_but_has_no_dispatched_effect(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("toolResult", [{"type": "text", "text": "Tool search not found"}],
                              toolCallId="absent", toolName="search", isError=True))
        self.assertEqual(graph.coverage()["orphan_failed_dispatch"], ["absent"])
        graph.assert_known_tool_dispatch_coverage()
        with self.assertRaises(ValueError):
            graph.assert_complete_process()

    def test_candidates_do_not_look_into_future(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Find the owner."))
        graph.ingest(2, event("assistant", [call("r", "read", {"path": "contacts.md"})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "owner@example.com"}], toolCallId="r"))
        self.assertFalse(graph.candidate_sources("owner@example.com", before_seq=3))
        self.assertEqual(len(graph.candidate_sources("owner@example.com", before_seq=4)), 1)

    def test_opaque_prior_shell_operation_makes_readback_source_untrusted(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Read contacts.md to identify the owner."))
        graph.ingest(2, event("assistant", [call("x", "exec", {"command": "some opaque operation"})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "ok"}], toolCallId="x"))
        graph.ingest(4, event("assistant", [call("r", "read", {"path": "contacts.md"})]))
        graph.ingest(5, event("toolResult", [{"type": "text", "text": "owner@example.com"}], toolCallId="r"))
        source = graph.candidate_sources("owner@example.com", before_seq=6)[0]
        self.assertTrue(source["path_written_earlier_in_session"])

    def test_patch_paths_become_individual_reported_states(self):
        graph = NativeOpenClawGraph()
        patch = "*** Begin Patch\n*** Add File: note.md\n+hello\n*** Update File: MEMORY.md\n@@\n-old\n+new\n*** End Patch"
        graph.ingest(1, event("user", "Update the files."))
        graph.ingest(2, event("assistant", [call("p", "apply_patch", {"input": patch})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "Done"}], toolCallId="p"))
        self.assertEqual({item["path"] for item in graph.writes}, {"note.md", "MEMORY.md"})
        self.assertIsNotNone(graph.graph.state_node("workspace://note.md"))
        self.assertIsNotNone(graph.graph.state_node("workspace://MEMORY.md"))

    def test_final_external_state_confirms_exact_sent_record(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Send to owner@example.com."))
        args = {"recipients": ["owner@example.com"], "subject": "Update", "body": "Done"}
        graph.ingest(2, event("assistant", [call("s", "agentdojo__send_email", args)]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "sent"}], toolCallId="s"))
        graph.ingest_external_state_diff({"inbox": {"sent": []}},
                                         {"inbox": {"sent": [{"id_": "42", **args}]}})
        self.assertEqual(graph.coverage()["externally_verified_sends"], 1)
        self.assertTrue(any(edge.edge_type is EdgeType.CONFIRMS for edge in graph.graph.edges))

    def test_unknown_tool_is_recorded_but_fails_strict_process_contract(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Do the task."))
        graph.ingest(2, event("assistant", [call("x", "unmapped_tool", {"value": "abcde"})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "ok"}], toolCallId="x"))
        self.assertEqual(graph.coverage()["unknown_effect_calls"], ["x"])
        with self.assertRaises(ValueError):
            graph.assert_complete_process()

    def test_apparent_read_side_effect_and_mock_exec_are_typed_separately(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Check my inbox and inspect the simulated command."))
        graph.ingest(2, event("assistant", [call("u", "agentdojo__get_unread_emails", {})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "[]"}], toolCallId="u"))
        graph.ingest(4, event("assistant", [call("m", "agentdojo__mock_exec", {"command": "echo hi"})]))
        graph.ingest(5, event("toolResult", [{"type": "text", "text": "fixture"}], toolCallId="m"))
        unread = graph.graph.node(graph.calls["u"]["effect_id"]).data
        simulated = graph.graph.node(graph.calls["m"]["effect_id"]).data
        self.assertEqual(unread["kind"], "write")
        self.assertEqual(unread["target"], "external://inbox/read_flags")
        self.assertTrue(unread["persistent"])
        self.assertEqual(simulated["kind"], "execute")
        self.assertFalse(simulated["persistent"])
        self.assertTrue(simulated["target"].startswith("simulated://"))

    def test_cloud_file_mutations_do_not_masquerade_as_workspace_writes(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Create then remove a cloud file."))
        graph.ingest(2, event("assistant", [call("c", "agentdojo__create_file", {
            "filename": "note.md", "content": "hello"})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "created"}], toolCallId="c"))
        graph.ingest(4, event("assistant", [call("d", "agentdojo__delete_file", {"file_id": "42"})]))
        graph.ingest(5, event("toolResult", [{"type": "text", "text": "deleted"}], toolCallId="d"))
        self.assertEqual(graph.coverage()["file_writes"], 0)
        self.assertEqual(graph.coverage()["cloud_mutations"], 2)
        self.assertEqual(graph.graph.node(graph.calls["c"]["effect_id"]).data["target"],
                         "cloud://filename/note.md")
        self.assertEqual(graph.graph.node(graph.calls["d"]["effect_id"]).data["target"],
                         "cloud://file/42")

    def test_audit_export_retains_exact_contents_when_requested(self):
        graph = NativeOpenClawGraph()
        graph.ingest(1, event("user", "Send to owner@example.com."))
        graph.ingest(2, event("assistant", [call("s", "agentdojo__send_email", {
            "recipients": ["owner@example.com"], "subject": "Update", "body": "Done"})]))
        graph.ingest(3, event("toolResult", [{"type": "text", "text": "sent"}], toolCallId="s"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            graph.save_audit(path)
            saved = json.loads(path.read_text(encoding="utf-8"))
            raw = list(saved["content_index"]["raw_texts"].values())
            self.assertTrue(any("owner@example.com" in text for text in raw))
            self.assertTrue(any("sent" in text for text in raw))
            with self.assertRaises(FileExistsError):
                graph.save_audit(path)


if __name__ == "__main__":
    unittest.main()
