"""Streaming pre-call evaluation uses only prior trusted user and graph facts."""

from __future__ import annotations

import unittest

from greatwallguard.authorization_rules import ConservativeLocalExtractor, default_email_environment
from greatwallguard.online_auditor import StreamingAuditor


def event(role, content=None, **kwargs):
    return {"type": "message", "message": {"role": role, "content": content, **kwargs}}


def call(call_id, recipient):
    return {"type": "toolCall", "id": call_id, "name": "agentdojo__send_email",
            "arguments": {"recipients": [recipient], "subject": "Update", "body": "Done"}}


class StreamingAuditorTests(unittest.TestCase):
    def test_first_send_is_allowed_but_a_second_one_exceeds_grant(self):
        auditor = StreamingAuditor(default_email_environment(), ConservativeLocalExtractor())
        auditor.ingest(1, event("user", "Send one email to owner@example.com with subject 'Update' and body 'Done'."))
        first = auditor.ingest(2, event("assistant", [call("s1", "owner@example.com")]))
        self.assertEqual(first[0]["verdict"], "allow_candidate")
        self.assertTrue(auditor.graph.graph.node(auditor.graph.calls["s1"]["action_id"])
                        .data["authorization_audit"]["evaluated_before_call"])
        auditor.ingest(3, event("toolResult", [{"type": "text", "text": "sent"}], toolCallId="s1"))
        second = auditor.ingest(4, event("assistant", [call("s2", "other@example.com")]))
        self.assertEqual(second[0]["verdict"], "alert")
        self.assertEqual(second[0]["reason"], "no_current_user_grant")

    def test_extractor_failure_becomes_review_not_empty_authorization(self):
        class BrokenExtractor:
            def propose(self, **kwargs):
                raise RuntimeError("bad parser")

        auditor = StreamingAuditor(default_email_environment(), BrokenExtractor())
        auditor.ingest(1, event("user", "Send one email to owner@example.com."))
        self.assertEqual(len(auditor.extraction_errors), 1)
        decision = auditor.ingest(2, event("assistant", [call("s1", "owner@example.com")]))
        self.assertEqual(decision[0]["verdict"], "review")

    def test_nontext_user_event_is_recorded_and_never_grants_authority(self):
        auditor = StreamingAuditor(default_email_environment(), ConservativeLocalExtractor())
        auditor.ingest(1, event("user", [{"type": "image", "data": "opaque"}]))
        self.assertEqual(auditor.graph.coverage()["native_events_with_audit_anchor"], 1)
        self.assertEqual(auditor.extraction_errors[0]["kind"], "UninterpretableUserContent")
        decision = auditor.ingest(2, event("assistant", [call("s1", "owner@example.com")]))
        self.assertEqual(decision[0]["verdict"], "review")


if __name__ == "__main__":
    unittest.main()
