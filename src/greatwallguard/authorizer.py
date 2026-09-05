"""Deterministic task-scope authorization over proposed Effects."""

from __future__ import annotations

from typing import Iterable

from .graph import EffectGraph
from .model import Decision, DecisionKind, Effect, EffectType, TaskScope


class EffectAuthorizer:
    """Checks effects before they are committed to the environment."""

    def __init__(self, scope: TaskScope) -> None:
        self.scope = scope

    def check(
        self,
        effects: Iterable[Effect],
        graph: EffectGraph,
        *,
        action_id: str | None = None,
    ) -> Decision:
        effects = tuple(effects)
        effect_ids = tuple(effect.id for effect in effects if effect.id)
        for effect in effects:
            if effect.kind is EffectType.UNKNOWN:
                return Decision(DecisionKind.ASK, "tool has no registered Effect contract", effect_ids, action_id)
            if not self.scope.permits_effect(effect):
                return Decision(
                    DecisionKind.BLOCK,
                    f"Effect {effect.kind.value} on {effect.target} is outside TaskScope",
                    effect_ids,
                    action_id,
                )

            # Authority does not flow from tool returns, files, or memory.
            # They may provide data for an already authorized action, but cannot
            # add a new external side effect to the scope.
            source_integrities = graph.source_integrities(effect.source_node_ids)
            if source_integrities.intersection({"untrusted", "external", "memory", "file"}) and effect.kind in {
                EffectType.SEND,
                EffectType.EXECUTE,
                EffectType.PERMISSION_CHANGE,
            }:
                return Decision(
                    DecisionKind.BLOCK,
                    "untrusted data cannot grant authority for a high-impact Effect",
                    effect_ids,
                    action_id,
                )
        return Decision(DecisionKind.ALLOW, "all Effects fit the task scope", effect_ids, action_id)

