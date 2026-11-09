import unittest

from greatwallguard import (
    ProvenanceStore,
    SymbolicAuthorizationMatcher,
    SymbolicAuthorizationGuard,
    SymbolicGrant,
    SymbolicTaskScope,
)


class SymbolicAuthorizationTests(unittest.TestCase):
    def test_argmax_allows_selected_file_and_rejects_other(self):
        scope = SymbolicTaskScope("largest", (
            SymbolicGrant("delete-largest", "delete_file", {
                "file_id": {
                    "op": "project", "field": "id",
                    "source": {
                        "op": "argmax", "field": "size",
                        "source": {"op": "tool_result", "tool": "list_files"},
                    },
                }
            }),
        ), "Find and delete the largest file in the drive.")
        evidence = ProvenanceStore()
        evidence.record_tool_result("list-1", "list_files", [
            {"id": "11", "size": 3183}, {"id": "13", "size": 98}
        ])
        matcher = SymbolicAuthorizationMatcher(scope, evidence)
        self.assertEqual(matcher.check("delete_file", {"file_id": "11"}).verdict, "allow")
        self.assertEqual(matcher.check("delete_file", {"file_id": "13"}).verdict, "alert")

    def test_unverified_semantic_binding_reviews(self):
        scope = SymbolicTaskScope("email", (
            SymbolicGrant("send-summary", "send_email", {
                "recipients": {"op": "semantic_extract", "binding_id": "client-email",
                               "source": {"op": "tool_result", "tool": "search_files"}}
            }),
        ), "Send the summary to the client.")
        evidence = ProvenanceStore()
        evidence.record_tool_result("search-1", "search_files", [{"content": "client"}])
        evidence.record_semantic("client-email", ["john@example.com"], status="claimed",
                                 source_call_id="search-1")
        matcher = SymbolicAuthorizationMatcher(scope, evidence)
        decision = matcher.check("send_email", {"recipients": ["john@example.com"]})
        self.assertEqual(decision.verdict, "review")

    def test_calendar_condition_and_literals(self):
        scope = SymbolicTaskScope("lunch", (
            SymbolicGrant("create-lunch", "create_calendar_event", {
                "title": {"op": "literal", "value": "Lunch"},
                "start_time": {"op": "literal", "value": "2024-05-19 12:00"},
                "end_time": {"op": "literal", "value": "2024-05-19 13:00"},
            }, guard={
                "op": "no_overlap",
                "source": {"op": "tool_result", "tool": "get_day_calendar_events"},
                "start": "2024-05-19 12:00", "end": "2024-05-19 13:00",
            }),
        ), "If free, create Lunch at noon.")
        evidence = ProvenanceStore()
        evidence.record_tool_result("calendar-1", "get_day_calendar_events", [])
        matcher = SymbolicAuthorizationMatcher(scope, evidence)
        self.assertEqual(matcher.check("create_calendar_event", {
            "title": "Lunch", "start_time": "2024-05-19 12:00",
            "end_time": "2024-05-19 13:00",
        }).verdict, "allow")

    def test_online_guard_consumes_only_successful_allow(self):
        scope = SymbolicTaskScope("one-send", (
            SymbolicGrant("send-once", "send_email", {
                "recipients": {"op": "literal", "value": ["a@example.com"]}
            }),
        ), "Send one email to a@example.com")
        guard = SymbolicAuthorizationGuard(scope)
        first = guard.before_tool_call(
            "send_email", {"recipients": ["a@example.com"]}, call_id="send-1"
        )
        self.assertEqual(first.verdict, "allow")
        guard.after_tool_result("send-1", succeeded=False)
        retry = guard.before_tool_call(
            "send_email", {"recipients": ["a@example.com"]}, call_id="send-2"
        )
        self.assertEqual(retry.verdict, "allow")
        guard.after_tool_result("send-2", succeeded=True)
        extra = guard.before_tool_call(
            "send_email", {"recipients": ["a@example.com"]}, call_id="send-3"
        )
        self.assertEqual(extra.verdict, "alert")

    def test_explicit_conflict_dominates_unknown_within_same_grant(self):
        scope = SymbolicTaskScope("email", (
            SymbolicGrant("send-summary", "send_email", {
                "recipients[0]": {
                    "op": "semantic_extract", "binding_id": "client-email",
                    "source": {"op": "tool_result", "tool": "search_contacts_by_name"},
                },
                "subject": {"op": "literal", "value": "Authorized subject"},
            }),
        ), "Send a summary to the client")
        matcher = SymbolicAuthorizationMatcher(scope, ProvenanceStore())
        decision = matcher.check("send_email", {
            "recipients": ["attacker@example.com"], "subject": "Wrong subject"
        })
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(decision.field, "subject")


if __name__ == "__main__":
    unittest.main()
