"""Streaming authorization/graph adapter with a pre-tool-call decision point.

This is an embeddable event adapter, not an installed OpenClaw interception
plugin. Replay and a future native hook should call the same `ingest` method.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .authorization_rules import (AuthorizationLedger, MatchDecision,
                                  ToolEnvironment, TurnExtractor,
                                  commit_success, match_before_call)
from .native_openclaw_graph import NativeOpenClawGraph


@dataclass
class StreamingAuditor:
    environment: ToolEnvironment
    extractor: TurnExtractor
    graph: NativeOpenClawGraph = field(default_factory=NativeOpenClawGraph)
    ledger: AuthorizationLedger = field(init=False)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    extraction_errors: list[dict[str, Any]] = field(default_factory=list)
    pending: dict[str, MatchDecision] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.ledger = AuthorizationLedger(self.environment)

    def ingest(self, seq: int, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Ingest one native event; return decisions made *before* its calls.

        A future runtime hook must invoke this before dispatching the proposed
        tool calls. Passing a transcript afterwards preserves evaluation
        order but does not itself enforce a block.
        """
        new_decisions: list[dict[str, Any]] = []
        if event.get("type") == "message":
            message = event.get("message") or {}
            role = message.get("role")
            if role == "user":
                user_text = message.get("content")
                if not isinstance(user_text, str) or not user_text.strip():
                    # The graph still receives the exact native event. The
                    # authorization extractor cannot safely interpret this
                    # non-text/empty turn, so it creates review state only.
                    representation = json.dumps(user_text, ensure_ascii=False, sort_keys=True)
                    self.extraction_errors.append({"seq": seq, "kind": "UninterpretableUserContent",
                                                   "message": "non-text or empty user turn"})
                    effects = sorted({spec.effect for spec in self.environment.tools})
                    self.ledger.apply_trusted_turn(
                        representation,
                        {"add": [], "revoke": [], "suspend": [],
                         "unresolved": [{"effect": effect, "evidence_quote": representation,
                                         "reason": "non_text_or_empty_user_turn"}
                                        for effect in effects]},
                        turn=len(self.ledger.user_messages) + 1)
                else:
                    try:
                        self.ledger.extract_turn(user_text, self.extractor)
                    except Exception as error:
                        self.extraction_errors.append({"seq": seq, "kind": type(error).__name__,
                                                       "message": str(error)[:160]})
                        # Extractor failure is a review state, never a new grant.
                        effects = sorted({spec.effect for spec in self.environment.tools})
                        self.ledger.apply_trusted_turn(
                            user_text,
                            {"add": [], "revoke": [], "suspend": [],
                             "unresolved": [{"effect": effect, "evidence_quote": user_text,
                                             "reason": "extractor_or_validator_failure"}
                                            for effect in effects]},
                            turn=len(self.ledger.user_messages) + 1)
            elif role == "assistant":
                for part in message.get("content") or []:
                    if not isinstance(part, dict) or part.get("type") != "toolCall":
                        continue
                    tool, call_id = part.get("name"), part.get("id")
                    if not isinstance(tool, str) or not isinstance(call_id, str):
                        continue
                    if self.environment.by_name(tool) is None:
                        continue
                    decision = match_before_call(
                        self.ledger, tool_name=tool, arguments=part.get("arguments") or {},
                        evidence=self.graph, before_seq=seq)
                    row = {"seq": seq, "turn": len(self.ledger.user_messages),
                           "call_id": call_id, "tool": tool,
                           "arguments": part.get("arguments") or {},
                           "verdict": decision.verdict, "reason": decision.reason,
                           "grant_id": decision.grant_id,
                           "source_evidence": list(decision.evidence)}
                    self.decisions.append(row)
                    new_decisions.append(row)
                    self.pending[call_id] = decision
            elif role == "toolResult":
                call_id = message.get("toolCallId")
                decision = self.pending.pop(call_id, None)
                if decision and not message.get("isError"):
                    commit_success(self.ledger, decision)
        self.graph.ingest(seq, event)
        for row in new_decisions:
            call = self.graph.calls.get(row["call_id"])
            if call is not None:
                self.graph.graph.node(call["action_id"]).data["authorization_audit"] = {
                    "verdict": row["verdict"], "reason": row["reason"],
                    "grant_id": row["grant_id"], "decision_seq": seq,
                    "evaluated_before_call": True,
                }
        return new_decisions
