"""Reusable online authorization guard for tool-using agents.

The guard has a deliberately small runtime surface:

``on_user_message`` -> ``before_tool_call`` -> ``after_tool_result``.

It consumes trusted user messages and proposed tool calls only.  Dataset
labels, success oracles, attack goals, and future tool results are not inputs
to a decision.  Unknown semantics are returned as REVIEW rather than silently
treated as authority.
"""

from __future__ import annotations

import copy
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping
from urllib.parse import urlparse


SCHEMA_VERSION = "greatwallguard-programmatic-v0.1"


@dataclass(frozen=True)
class GuardDecision:
    """Decision produced before a tool is dispatched."""

    verdict: str  # allow | review | alert
    reason: str
    possible_false_positive: bool
    uncertainty: str | None = None
    evidence: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


READ_ONLY_TOOLS = frozenset({
    "search_emails", "search_files_by_filename", "search_files", "list_files",
    "get_received_emails", "get_file_by_id", "get_sent_emails", "mock_scheduler_list",
    "get_current_day", "get_unread_emails", "get_draft_emails", "search_calendar_events",
    "get_day_calendar_events", "search_contacts_by_email", "search_contacts_by_name",
    "mock_document_open",
})

OBSERVATION_TOOLS = frozenset({
    "mock_network_list_hosts", "mock_process_list", "mock_callback_status",
})

PERSISTENT_TOOLS = frozenset({
    "send_email", "share_file", "create_calendar_event", "delete_file", "create_file",
    "append_to_file", "mock_scheduler_create", "mock_scheduler_advance",
    "mock_network_scan", "mock_web_fetch", "reschedule_calendar_event",
    "add_calendar_event_participants", "mock_exec",
})

ADDRESS = r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"
SEND = re.compile(rf"\bsend\b[^.!?]{{0,220}}?\bto\s+({ADDRESS})\s+with subject\s+['\"]([^'\"]+)['\"]", re.I)
ORDINAL_SEND = re.compile(rf"\b(?:first|second|third)\s+to\s+({ADDRESS})\s+with subject\s+['\"]([^'\"]+)['\"]", re.I)
FILE_ID = re.compile(r"\bfile[_ ]id\s*[= ]\s*['\"]?(\d+)\b", re.I)
CALENDAR_CREATE = re.compile(r"\b(?:create|add)\b[^.!?]{0,130}?\bevent\b", re.I)
VAGUE = re.compile(
    r"\b(?:continue|resume|finish|carry forward|carry out|prepare)\b[^.!?;]{0,120}?"
    r"\b(?:remaining|pending|current|recorded|from the messages|handoff|setup|communication|work|disposition)\b[^.!?;]*",
    re.I,
)
HOST = re.compile(r"\b(?:https?://)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.(?:internal|local|test|com|net|org))\b", re.I)
EMAIL = re.compile(ADDRESS, re.I)
DATETIME = re.compile(r"\b(20\d\d-\d\d-\d\d(?:\s+(?:at\s+)?\d\d?:\d\d)?)\b", re.I)


def _norm(value: Any) -> Any:
    if isinstance(value, list):
        return sorted(str(item).casefold() for item in value)
    return str(value).casefold()


def _extract_base(message: str, turn: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Conservative local grammar retained as the v0.1 reference extractor."""
    commitments: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    ordinal = list(ORDINAL_SEND.finditer(message))
    send_matches = ordinal if len(ordinal) >= 2 else list(SEND.finditer(message))
    for match in send_matches:
        before = message[max(0, match.start() - 20):match.start()].casefold()
        if re.search(r"\b(?:do not|don't|never|without)\s*$", before):
            continue
        commitments.append({"turn": turn, "operation": "send_email",
                            "destination": match.group(1).casefold(), "subject": match.group(2),
                            "evidence_span": match.group(0)})
    body = re.search(r"\bbody\s+['\"]([^'\"]+)['\"]", message, re.I)
    sends = [item for item in commitments if item["operation"] == "send_email"]
    if body and len(sends) == 1:
        sends[0]["body"] = body.group(1)

    if re.search(r"\b(?:share|grant)\b", message, re.I) and not re.search(
            r"\b(?:do not|don't|never)\s+share\b", message, re.I):
        ids = list(FILE_ID.finditer(message))
        recipients = re.findall(ADDRESS, message, re.I)
        destination = recipients[0].casefold() if recipients else None
        permission = "rw" if re.search(r"read-write|editor access", message, re.I) else (
            "r" if "read-only" in message.casefold() else None)
        if ids:
            for match in ids:
                commitments.append({"turn": turn, "operation": "share_file",
                                    "object_id": match.group(1), "destination": destination,
                                    "permission": permission, "evidence_span": match.group(0)})
        else:
            files = re.findall(r"\b[\w.-]+\.(?:docx|xlsx|pdf|txt|md)\b", message, re.I)
            commitments.append({"turn": turn, "operation": "share_file",
                                "object_name": files[0] if files else None,
                                "destination": destination, "permission": permission,
                                "evidence_span": message})

    for match in CALENDAR_CREATE.finditer(message):
        commitments.append({"turn": turn, "operation": "create_calendar_event",
                            "object_name": None, "evidence_span": match.group(0)})
    disposable = re.search(
        r"\bcreate\s+one\s+disposable[^.!?]{0,160}?\bfile\b[^.!?]{0,100}?\bnamed\s+([\w.-]+)",
        message, re.I)
    if disposable:
        commitments.append({"turn": turn, "operation": "create_file",
                            "object_name": disposable.group(1), "evidence_span": disposable.group(0)})
    for match in VAGUE.finditer(message):
        fragment = match.group(0)
        lowered = fragment.casefold()
        possible = []
        if any(item in lowered for item in ("communication", "handoff", "routing")):
            possible.append("send_email")
        if "calendar" in message.casefold() or "event" in message.casefold():
            possible.append("create_calendar_event")
        if "collaboration" in lowered or "access" in lowered:
            possible.append("share_file")
        if "disposition" in lowered:
            possible.append("delete_file")
        unresolved.append({"turn": turn, "evidence_span": fragment,
                           "could_authorize": sorted(set(possible)),
                           "reason": "context_dependent_continuation"})
    return commitments, unresolved


class ProgrammaticAuthorizationGuard:
    """Stateful v0.1 authorization guard with bounded, serializable state."""

    def __init__(self) -> None:
        self.commitments: list[dict[str, Any]] = []
        self.unresolved: list[dict[str, Any]] = []
        self.consumed: set[int] = set()
        self.pending: dict[str, int | None] = {}
        self.extended_grants: list[dict[str, Any]] = []
        self.extended_unresolved: list[dict[str, Any]] = []
        self.extended_consumed: set[int] = set()
        self.extended_pending: dict[str, int | None] = {}
        self.trusted_turns: list[dict[str, Any]] = []

    def on_user_message(self, message: str, *, turn: int, trusted: bool = True) -> None:
        """Update authority from one ordered, authentic user message."""
        if not trusted:
            return
        if not isinstance(message, str) or not message.strip():
            raise ValueError("trusted user message must be non-empty text")
        if self.trusted_turns and turn < int(self.trusted_turns[-1]["turn"]):
            raise ValueError("trusted turns must be nondecreasing")
        self.trusted_turns.append({"turn": turn, "message": message})
        commitments, unresolved = _extract_base(message, turn)
        self.commitments.extend(commitments)
        self.unresolved.extend(unresolved)
        self._extract_extended(message, turn)

    def _grant(self, turn: int, tool: str, parameters: dict[str, Any],
               unbound: set[str], evidence: str) -> None:
        self.extended_grants.append({"turn": turn, "tool": tool, "parameters": parameters,
                                     "unbound": sorted(unbound), "evidence": evidence})

    def _unresolved(self, turn: int, tool: str, evidence: str, reason: str) -> None:
        self.extended_unresolved.append({"turn": turn, "tool": tool,
                                         "evidence": evidence, "reason": reason})

    def _extract_extended(self, text: str, turn: int) -> None:
        lowered = text.casefold()
        hosts = list(dict.fromkeys(match.group(1).casefold() for match in HOST.finditer(text)))
        if hosts and re.search(r"\b(?:scan|verify|check|probe|inventory)\b", text, re.I):
            ports = [443] if re.search(r"\bhttps\b|\b443\b", text, re.I) else []
            self._grant(turn, "mock_network_scan", {"target": hosts[0], "ports": ports},
                        set() if ports else {"ports"}, text)
            self._grant(turn, "mock_web_fetch", {"host": hosts[0]}, set(), text)
        if re.search(r"\breschedule\b", text, re.I):
            when = DATETIME.search(text)
            self._grant(turn, "reschedule_calendar_event",
                        {"new_start_time": when.group(1).replace(" at ", " ") if when else None},
                        {"event_id", "new_end_time"} | (set() if when else {"new_start_time"}), text)
        if re.search(r"\badd\b.+\bparticipants?\b|\badd also\b", text, re.I):
            participants = sorted({item.casefold() for item in EMAIL.findall(text)})
            self._grant(turn, "add_calendar_event_participants", {"participants": participants},
                        {"event_id"} | (set() if participants else {"participants"}), text)
        explicit_delete = re.search(r"\b(?:delete|remove)\b[^.!?]{0,120}\bfile\b", text, re.I)
        if explicit_delete and not re.search(
                r"\b(?:do not|don't|never)\b[^.!?]{0,30}\b(?:delete|remove)\b", text, re.I):
            file_id = re.search(r"\bfile(?:_id| id)?\s*[=: ]\s*['\"]?([\w.-]+)", text, re.I)
            self._grant(turn, "delete_file", {"file_id": file_id.group(1) if file_id else None},
                        set() if file_id else {"file_id"}, explicit_delete.group(0))
        elif re.search(r"\b(?:process|dispose|clean up|carry out|complete|continue)\b[^.!?]{0,160}"
                       r"\b(?:queue|disposition|closeout|disposable|outstanding|listed item|recorded item)\b", text, re.I):
            self._unresolved(turn, "delete_file", text,
                             "business action may imply deletion but object/effect is not explicit")
        explicit_schedule = re.search(
            r"\b(?:schedule|create|set up)\b[^.!?]{0,100}\b(?:task|reminder|automation|job|follow-up)\b", text, re.I)
        if explicit_schedule and not re.search(
                r"\b(?:do not|don't|never)\b[^.!?]{0,30}\b(?:schedule|create|set up)\b", text, re.I):
            name = re.search(r"\b(?:named?|task_name)\s*['\"]([^'\"]+)['\"]", text, re.I)
            self._grant(turn, "mock_scheduler_create", {"task_name": name.group(1) if name else None},
                        set() if name else {"task_name", "schedule", "payload"}, explicit_schedule.group(0))
        elif re.search(r"\b(?:next cycle|next session|follow-up|scheduled|pending|continuity)\b", lowered):
            self._unresolved(turn, "mock_scheduler_create", text,
                             "continuity language may imply future work but not a scheduler registration")
            self._unresolved(turn, "mock_scheduler_advance", text,
                             "continuity language does not explicitly authorize triggering scheduled work")
        explicit_advance = re.search(r"\b(?:advance|trigger|run)\b[^.!?]{0,100}\b(?:scheduler|scheduled task|job)\b", text, re.I)
        if explicit_advance:
            ticks = re.search(r"\b(\d+)\s+(?:tick|step|cycle)s?\b", explicit_advance.group(0), re.I)
            self._grant(turn, "mock_scheduler_advance", {"ticks": int(ticks.group(1)) if ticks else None},
                        set() if ticks else {"ticks"}, explicit_advance.group(0))
        explicit_exec = re.search(r"\b(?:run|execute)\b[^.!?]{0,40}\b(?:command|shell|script)\b", text, re.I)
        if explicit_exec:
            command = re.search(r"['\"]([^'\"]+)['\"]", explicit_exec.group(0))
            self._grant(turn, "mock_exec", {"command": command.group(1) if command else None},
                        set() if command else {"command"}, explicit_exec.group(0))
        elif re.search(r"\b(?:record|preserve|prepare|closeout)\b", lowered):
            self._unresolved(turn, "mock_exec", text,
                             "task wording may require local state work but does not name a command")
        create = re.search(r"\b(?:create|save|write)\b[^.!?]{0,120}\bfile\b[^.!?]{0,80}\b(?:named|called)\s+([\w.-]+)", text, re.I)
        if create:
            self._grant(turn, "create_file", {"filename": create.group(1)}, {"content"}, create.group(0))
        elif re.search(r"\b(?:report|record|handoff summary)\b", lowered):
            self._unresolved(turn, "create_file", text, "requested output may be conversational or a file")
            self._unresolved(turn, "append_to_file", text, "requested output may append an existing log")
        append = re.search(r"\bappend\b[^.!?]{0,160}\b(?:file|log)\b", text, re.I)
        if append:
            file_id = re.search(r"\b(?:file_id|file id|log)\s*[=: ]\s*['\"]?([\w.-]+)", text, re.I)
            self._grant(turn, "append_to_file", {"file_id": file_id.group(1) if file_id else None},
                        {"content"} | (set() if file_id else {"file_id"}), append.group(0))
        elif re.search(r"\b(?:record|update)\b[^.!?]{0,80}\b(?:log|file)\b", lowered):
            self._unresolved(turn, "append_to_file", text, "write requested without a bound object/content")

    @staticmethod
    def _matching_fields(commitment: Mapping[str, Any], tool: str,
                         args: Mapping[str, Any]) -> tuple[bool, str | None]:
        if commitment["operation"] != tool:
            return False, "operation"
        destination = commitment.get("destination")
        if destination:
            recipients = args.get("recipients") or []
            recipients = [recipients] if isinstance(recipients, str) else recipients
            observed = {str(item).casefold() for item in recipients}
            observed |= {str(item).casefold() for field in ("cc", "bcc") for item in (args.get(field) or [])}
            if args.get("email"):
                observed.add(str(args["email"]).casefold())
            if destination.casefold() not in observed or len(observed) != 1:
                return False, "destination"
        checks = (("object_id", "file_id"), ("permission", "permission"),
                  ("subject", "subject"), ("body", "body"))
        for expected, actual in checks:
            if commitment.get(expected) and str(args.get(actual)) != str(commitment[expected]):
                return False, expected
        if commitment.get("object_name") and tool == "create_file":
            if str(args.get("filename") or args.get("name") or "").casefold() != str(commitment["object_name"]).casefold():
                return False, "object_name"
        return True, None

    def before_tool_call(self, tool: str, args: Mapping[str, Any], *, turn: int,
                         call_id: str) -> GuardDecision:
        """Decide before execution.  REVIEW is the fail-safe for uncertainty."""
        if call_id in self.pending or call_id in self.extended_pending:
            raise ValueError(f"call_id already pending: {call_id}")
        args = dict(args)
        if tool in OBSERVATION_TOOLS:
            self.pending[call_id] = None
            return GuardDecision("allow", "nonpersistent_observation_contract", False)
        if tool in READ_ONLY_TOOLS:
            self.pending[call_id] = None
            return GuardDecision("allow", "read_only_tool", False)
        if tool in {"mock_network_scan", "mock_web_fetch", "reschedule_calendar_event",
                    "add_calendar_event_participants", "delete_file", "mock_scheduler_create",
                    "mock_scheduler_advance", "mock_exec", "create_file", "append_to_file"}:
            return self._before_extended(tool, args, turn=turn, call_id=call_id)
        if tool not in PERSISTENT_TOOLS:
            self.pending[call_id] = None
            return GuardDecision("review", "unmapped_tool_effect", True, "tool_effect_contract_missing")
        available = [(index, item) for index, item in enumerate(self.commitments)
                     if index not in self.consumed and index not in self.pending.values()
                     and int(item["turn"]) <= turn and item["operation"] != "write_workspace_file"]
        exact = [(index, item) for index, item in available if self._matching_fields(item, tool, args)[0]]
        if exact:
            index, item = exact[0]
            self.pending[call_id] = index
            if tool == "send_email" and "body" not in item:
                return GuardDecision("review", "email_body_not_bound_by_user_request", True,
                                     "content_may_be_legitimately_derived_from_task_data", item["evidence_span"])
            if tool == "share_file" and "object_id" not in item:
                return GuardDecision("review", "share_object_not_bound_by_user_request", True,
                                     "file_identity_may_be_resolved_from_task_data", item["evidence_span"])
            if tool == "create_calendar_event":
                return GuardDecision("review", "calendar_content_not_bound_by_user_request", True,
                                     "title_time_and_attendees_need_contextual_binding", item["evidence_span"])
            return GuardDecision("allow", "matches_explicit_user_commitment", False,
                                 evidence=item["evidence_span"])
        self.pending[call_id] = None
        same = [(item, self._matching_fields(item, tool, args)[1]) for _, item in available
                if item["operation"] == tool]
        if same:
            item, field = same[0]
            return GuardDecision("review", f"{field}_differs_from_user_commitment", True,
                                 "may_be_resolved_from_task_data_or_parser_missed_a_variant", item["evidence_span"])
        contextual = [item for item in self.unresolved if int(item["turn"]) <= turn
                      and tool in item.get("could_authorize", [])]
        if contextual:
            return GuardDecision("review", "context_dependent_user_request", True,
                                 "normal_continuation_cannot_be_bound_from_user_text_alone",
                                 contextual[-1]["evidence_span"])
        return GuardDecision("alert", "no_matching_user_commitment", False)

    @staticmethod
    def _observed(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "mock_web_fetch":
            return {"host": (urlparse(str(args.get("url") or "")).hostname or "").casefold()}
        return dict(args)

    def _before_extended(self, tool: str, args: dict[str, Any], *, turn: int,
                         call_id: str) -> GuardDecision:
        observed = self._observed(tool, args)
        available = [(index, grant) for index, grant in enumerate(self.extended_grants)
                     if index not in self.extended_consumed and index not in self.extended_pending.values()
                     and grant["turn"] <= turn and grant["tool"] == tool]
        soft_conflict: tuple[int, dict[str, Any], str] | None = None
        for index, grant in available:
            conflict = False
            for field, expected in grant["parameters"].items():
                if field in grant["unbound"] or expected is None:
                    continue
                actual = observed.get(field)
                if field == "new_start_time" and actual is not None:
                    actual = str(actual)[:len(str(expected))]
                if _norm(actual) != _norm(expected):
                    conflict = True
                    if tool == "mock_network_scan" and field == "ports":
                        soft_conflict = (index, grant, field)
                    break
            if conflict:
                continue
            self.extended_pending[call_id] = index
            if grant["unbound"]:
                return GuardDecision("review", "known_effect_parameter_binding_unresolved", True,
                                     ",".join(grant["unbound"]), grant["evidence"])
            return GuardDecision("allow", "matches_extended_user_commitment", False,
                                 evidence=grant["evidence"])
        self.extended_pending[call_id] = None
        if soft_conflict is not None:
            return GuardDecision("review", "known_effect_parameter_binding_unresolved", True,
                                 "requested service matches but probe port set differs",
                                 soft_conflict[1]["evidence"])
        unresolved = [item for item in self.extended_unresolved
                      if item["turn"] <= turn and item["tool"] == tool]
        if unresolved:
            return GuardDecision("review", "known_effect_context_dependent_request", True,
                                 unresolved[-1]["reason"], unresolved[-1]["evidence"])
        if available:
            return GuardDecision("alert", "explicit_extended_parameter_violation", False)
        return GuardDecision("alert", "no_matching_extended_user_commitment", False)

    def after_tool_result(self, call_id: str, *, succeeded: bool) -> None:
        """Consume a single-use grant only after successful execution."""
        if call_id in self.extended_pending:
            index = self.extended_pending.pop(call_id)
            if succeeded and index is not None:
                self.extended_consumed.add(index)
            return
        if call_id not in self.pending:
            raise ValueError(f"unknown pending call_id: {call_id}")
        index = self.pending.pop(call_id)
        if succeeded and index is not None:
            self.consumed.add(index)

    def export_state(self) -> dict[str, Any]:
        """Return JSON-serializable state for restart and audit."""
        return {"schema": SCHEMA_VERSION, "trusted_turns": copy.deepcopy(self.trusted_turns),
                "commitments": copy.deepcopy(self.commitments), "unresolved": copy.deepcopy(self.unresolved),
                "consumed": sorted(self.consumed), "pending": copy.deepcopy(self.pending),
                "extended_grants": copy.deepcopy(self.extended_grants),
                "extended_unresolved": copy.deepcopy(self.extended_unresolved),
                "extended_consumed": sorted(self.extended_consumed),
                "extended_pending": copy.deepcopy(self.extended_pending)}

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "ProgrammaticAuthorizationGuard":
        """Restore only states created by the same algorithm schema."""
        if state.get("schema") != SCHEMA_VERSION:
            raise ValueError("unsupported guard state schema")
        guard = cls()
        for name in ("trusted_turns", "commitments", "unresolved", "extended_grants",
                     "extended_unresolved"):
            value = state.get(name)
            if not isinstance(value, list):
                raise ValueError(f"invalid state field: {name}")
            setattr(guard, name, copy.deepcopy(value))
        for name in ("consumed", "extended_consumed"):
            value = state.get(name)
            if not isinstance(value, list) or any(type(item) is not int for item in value):
                raise ValueError(f"invalid state field: {name}")
            setattr(guard, name, set(value))
        for name in ("pending", "extended_pending"):
            value = state.get(name)
            if not isinstance(value, Mapping):
                raise ValueError(f"invalid state field: {name}")
            setattr(guard, name, dict(value))
        return guard


# Backward-compatible name for frozen experiments.
ProgrammaticEffectGuardV1 = ProgrammaticAuthorizationGuard
PreCallDecision = GuardDecision
