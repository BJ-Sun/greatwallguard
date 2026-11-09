"""Finite user delegation objects for authorization DAGs."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping


DELEGATION_AUTHORITIES = frozenset({"facts", "fields", "selection", "effects"})


@dataclass(frozen=True)
class DelegationGrant:
    """Decision authority explicitly assigned by a trusted user message.

    ``effects`` is the strongest authority.  An effect delegation without a
    finite allowed effect/tool set is intentionally confirmation-only.
    """

    delegation_id: str
    source: str
    authority: str
    allowed_fields: tuple[str, ...] = ()
    allowed_effects: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    constraints: Mapping[str, Any] | None = None
    requires_confirmation: bool = False
    evidence: str = ""

    def __post_init__(self) -> None:
        if not self.delegation_id or not self.source:
            raise ValueError("delegation id and source must be non-empty")
        if self.authority not in DELEGATION_AUTHORITIES:
            raise ValueError(f"unsupported delegation authority: {self.authority}")
        if self.authority == "effects" and not (self.allowed_effects or self.allowed_tools):
            object.__setattr__(self, "requires_confirmation", True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "delegation_id": self.delegation_id,
            "source": self.source,
            "authority": self.authority,
            "allowed_fields": list(self.allowed_fields),
            "allowed_effects": list(self.allowed_effects),
            "allowed_tools": list(self.allowed_tools),
            "constraints": dict(self.constraints or {}),
            "requires_confirmation": self.requires_confirmation,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DelegationGrant":
        return cls(
            delegation_id=str(value.get("delegation_id", "")),
            source=str(value.get("source", "")),
            authority=str(value.get("authority", "")),
            allowed_fields=tuple(str(item) for item in value.get("allowed_fields", [])),
            allowed_effects=tuple(str(item) for item in value.get("allowed_effects", [])),
            allowed_tools=tuple(str(item) for item in value.get("allowed_tools", [])),
            constraints=dict(value.get("constraints", {})),
            requires_confirmation=bool(value.get("requires_confirmation", False)),
            evidence=str(value.get("evidence", "")),
        )


_QUOTED_SOURCE = re.compile(r"['\"]([^'\"]+\.(?:txt|docx?|pdf|xlsx?|md|json|csv))['\"]", re.I)
_URL_SOURCE = re.compile(r"\b(?:https?://|www\.)[^\s'\"]+", re.I)
_BROAD_EFFECT_DELEGATION = re.compile(
    r"\b(?:follow|execute)\s+(?:the\s+)?instructions?\b"
    r"|\bdo\s+all\s+(?:the\s+)?tasks?\b"
    r"|\b(?:complete|finish|perform|fulfill|achieve)\b[^.!?]{0,80}"
    r"\b(?:tasks?|homework|requests?|what\s+(?:he|she|they)\s+needs?)\b",
    re.I,
)


def infer_explicit_delegations(user_message: str) -> tuple[DelegationGrant, ...]:
    """Conservative deterministic fallback for explicit broad delegation.

    This recognizes only unmistakable user delegation phrases.  It never
    guesses a finite effect set, so broad requests require confirmation.
    """
    match = _BROAD_EFFECT_DELEGATION.search(user_message)
    if match is None:
        return ()
    source_match = _QUOTED_SOURCE.search(user_message) or _URL_SOURCE.search(user_message)
    source = source_match.group(1) if source_match and source_match.lastindex else (
        source_match.group(0) if source_match else "external_task_source"
    )
    return (DelegationGrant(
        delegation_id="delegation:0",
        source=source.rstrip(".,!"),
        authority="effects",
        requires_confirmation=True,
        evidence=match.group(0),
    ),)
