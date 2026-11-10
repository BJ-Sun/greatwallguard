"""Bounded runtime expansion of authorization DAGs from explicit delegation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class DeltaDisposition(str, Enum):
    ACCEPT = "accept"
    CONFIRM = "confirm"
    DENY = "deny"


@dataclass(frozen=True)
class DelegationEnvelope:
    """Authority that a trusted user intentionally assigns to a future source."""

    delegation_id: str
    source_kind: str
    source_selector: Mapping[str, Any]
    purpose: str
    allowed_effect_classes: tuple[str, ...]
    max_effects: int = 1
    require_authenticated_source: bool = True
    confirmation_effect_classes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObservedDelegatedSource:
    ref: str
    source_kind: str
    identity: Mapping[str, Any]
    authenticated: bool
    content: str


@dataclass(frozen=True)
class ProposedEffect:
    tool: str
    effect_class: str
    arguments: Mapping[str, Any]
    rationale: str = ""


@dataclass(frozen=True)
class AuthorizationDelta:
    delegation_id: str
    source_ref: str
    effects: tuple[ProposedEffect, ...]


@dataclass(frozen=True)
class DeltaValidation:
    disposition: DeltaDisposition
    reason: str
    accepted_effects: tuple[ProposedEffect, ...] = ()


class DynamicDelegationExpander:
    """Validate a model-proposed delta using finite host-side invariants."""

    def validate(
        self,
        envelope: DelegationEnvelope,
        source: ObservedDelegatedSource,
        delta: AuthorizationDelta,
    ) -> DeltaValidation:
        if delta.delegation_id != envelope.delegation_id:
            return DeltaValidation(DeltaDisposition.DENY, "delegation_id_mismatch")
        if delta.source_ref != source.ref or source.source_kind != envelope.source_kind:
            return DeltaValidation(DeltaDisposition.DENY, "delegated_source_mismatch")
        if envelope.require_authenticated_source and not source.authenticated:
            return DeltaValidation(DeltaDisposition.CONFIRM, "delegated_source_not_authenticated")
        if not self._selector_matches(envelope.source_selector, source.identity):
            return DeltaValidation(DeltaDisposition.DENY, "delegated_source_identity_mismatch")
        if not delta.effects or len(delta.effects) > envelope.max_effects:
            return DeltaValidation(DeltaDisposition.CONFIRM, "delegation_budget_exceeded")
        allowed = set(envelope.allowed_effect_classes)
        confirmation = set(envelope.confirmation_effect_classes)
        if any(effect.effect_class not in allowed | confirmation for effect in delta.effects):
            return DeltaValidation(DeltaDisposition.DENY, "effect_outside_delegated_envelope")
        if any(effect.effect_class in confirmation for effect in delta.effects):
            return DeltaValidation(DeltaDisposition.CONFIRM, "sensitive_delegated_effect")
        return DeltaValidation(DeltaDisposition.ACCEPT, "bounded_delegation_delta", delta.effects)

    @staticmethod
    def _selector_matches(selector: Mapping[str, Any], identity: Mapping[str, Any]) -> bool:
        for key, expected in selector.items():
            actual = identity.get(key)
            if actual is None:
                return False
            if isinstance(expected, (list, tuple, set)):
                if actual not in expected:
                    return False
            elif str(actual).casefold() != str(expected).casefold():
                return False
        return True
