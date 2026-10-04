#!/usr/bin/env python3
"""Pre-call Effect guard prototype.

Only trusted user messages grant authority. A proposed tool call is checked
before execution; the matching commitment is consumed only after success.
This module does not read case labels, oracles, graphs, or tool results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from effect_commitment_reference_pilot import extract
from effect_scope_pilot import PERSISTENT_TOOLS


READ_ONLY_TOOLS = {
    "search_emails", "search_files_by_filename", "search_files", "list_files",
    "get_received_emails", "get_file_by_id", "get_sent_emails", "mock_scheduler_list",
    "get_current_day", "get_unread_emails", "get_draft_emails", "search_calendar_events",
    "get_day_calendar_events", "search_contacts_by_email", "search_contacts_by_name",
    "mock_document_open",
}


@dataclass(frozen=True)
class PreCallDecision:
    verdict: str  # allow | review | alert
    reason: str
    possible_false_positive: bool
    uncertainty: str | None = None
    evidence: str | None = None


class OnlineEffectGuard:
    """Small, stateful pre-call interface suitable for a tool gateway hook.

    `review` is a soft alert, not an automatic block. `alert` is also advisory
    in this pilot: parser non-coverage must not silently stop legitimate work.
    """

    def __init__(self) -> None:
        self.commitments: list[dict[str, Any]] = []
        self.unresolved: list[dict[str, Any]] = []
        self.consumed: set[int] = set()
        self.pending: dict[str, int | None] = {}

    def on_user_message(self, message: str, *, turn: int, trusted: bool) -> None:
        if not trusted:
            return
        parsed = extract({"request_id": "online", "turns": [{"turn": turn, "user_message": message}]})
        # Bind an explicitly quoted body only when this turn has one send.
        # Otherwise the association is ambiguous and remains unresolved.
        sends = [x for x in parsed["commitments"] if x["operation"] == "send_email"]
        body = re.search(r"\bbody\s+['\"]([^'\"]+)['\"]", message, re.I)
        if body and len(sends) == 1:
            sends[0]["body"] = body.group(1)
        self.commitments.extend(parsed["commitments"])
        self.unresolved.extend(parsed["unresolved"])

    @staticmethod
    def _matching_fields(commitment: dict[str, Any], tool: str, args: dict[str, Any]) -> tuple[bool, str | None]:
        if commitment["operation"] != tool:
            return False, "operation"
        destination = commitment.get("destination")
        if destination:
            recipients = args.get("recipients") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            observed = {str(x).lower() for x in recipients}
            observed |= {str(x).lower() for field in ("cc", "bcc") for x in (args.get(field) or [])}
            if args.get("email"):
                observed.add(str(args["email"]).lower())
            if destination.lower() not in observed or len(observed) != 1:
                return False, "destination"
        if commitment.get("object_id") and str(args.get("file_id")) != str(commitment["object_id"]):
            return False, "object_id"
        if commitment.get("permission") and str(args.get("permission")) != str(commitment["permission"]):
            return False, "permission"
        if commitment.get("subject") and str(args.get("subject")) != str(commitment["subject"]):
            return False, "subject"
        if commitment.get("body") and str(args.get("body")) != str(commitment["body"]):
            return False, "body"
        if commitment.get("object_name") and tool == "create_file":
            if str(args.get("filename") or args.get("name") or "").casefold() != str(commitment["object_name"]).casefold():
                return False, "object_name"
        return True, None

    def before_tool_call(self, tool: str, args: dict[str, Any], *, turn: int, call_id: str) -> PreCallDecision:
        if call_id in self.pending:
            raise ValueError(f"call_id already pending: {call_id}")
        if tool in READ_ONLY_TOOLS:
            return PreCallDecision("allow", "read_only_tool", False)
        if tool not in PERSISTENT_TOOLS:
            self.pending[call_id] = None
            return PreCallDecision("review", "unmapped_tool_effect", True,
                                   "tool_effect_contract_missing")
        available = [(i, c) for i, c in enumerate(self.commitments)
                     if i not in self.consumed and i not in self.pending.values() and int(c["turn"]) <= turn
                     and c["operation"] != "write_workspace_file"]
        exact = [(i, c) for i, c in available if self._matching_fields(c, tool, args)[0]]
        if exact:
            index, item = exact[0]
            self.pending[call_id] = index
            if tool == "send_email" and "body" not in item:
                return PreCallDecision("review", "email_body_not_bound_by_user_request", True,
                                       "content_may_be_legitimately_derived_from_task_data", item["evidence_span"])
            if tool == "share_file" and "object_id" not in item:
                return PreCallDecision("review", "share_object_not_bound_by_user_request", True,
                                       "file_identity_may_be_resolved_from_task_data", item["evidence_span"])
            if tool == "create_calendar_event":
                return PreCallDecision("review", "calendar_content_not_bound_by_user_request", True,
                                       "title_time_and_attendees_need_contextual_binding", item["evidence_span"])
            return PreCallDecision("allow", "matches_explicit_user_commitment", False, evidence=item["evidence_span"])
        self.pending[call_id] = None
        same_operation = [(c, self._matching_fields(c, tool, args)[1]) for _, c in available if c["operation"] == tool]
        if same_operation:
            item, field = same_operation[0]
            return PreCallDecision("review", f"{field}_differs_from_user_commitment", True,
                                   "may_be_resolved_from_task_data_or_parser_missed_a_variant", item["evidence_span"])
        contextual = [c for c in self.unresolved if int(c["turn"]) <= turn and tool in c.get("could_authorize", [])]
        if contextual:
            return PreCallDecision("review", "context_dependent_user_request", True,
                                   "normal_continuation_cannot_be_bound_from_user_text_alone", contextual[-1]["evidence_span"])
        if tool in {"append_to_file", "create_file", "delete_file", "mock_scheduler_create", "mock_scheduler_advance"}:
            return PreCallDecision("review", "operation_not_extracted_from_user_request", True,
                                   "current_parser_does_not_cover_this_operation_or_resource_binding")
        return PreCallDecision("alert", "no_matching_user_commitment", False)

    def after_tool_result(self, call_id: str, *, succeeded: bool) -> None:
        if call_id not in self.pending:
            raise ValueError(f"unknown pending call_id: {call_id}")
        index = self.pending.pop(call_id)
        if succeeded and index is not None:
            self.consumed.add(index)
