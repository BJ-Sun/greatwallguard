"""Small runtime event envelope for measuring extraction coverage."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from .graph import digest, compact_summary


class TraceEventType(str, Enum):
    OBSERVATION = "observation"
    ACTION_PROPOSED = "action_proposed"
    AUTHORIZATION = "authorization"
    EFFECT_COMMITTED = "effect_committed"
    EFFECT_FAILED = "effect_failed"
    STATE_READ = "state_read"


@dataclass
class TraceEvent:
    event_id: str
    event_type: TraceEventType
    turn: int
    node_id: str | None = None
    related_ids: tuple[str, ...] = ()
    summary: str = ""
    payload_digest: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


class TraceRecorder:
    """Append-only events with bounded summaries and no raw payloads."""

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []
        self._counter = 0

    def record(
        self,
        event_type: TraceEventType,
        *,
        turn: int,
        node_id: str | None = None,
        related_ids: Iterable[str] = (),
        summary: str = "",
        payload: Any = None,
        data: dict[str, Any] | None = None,
    ) -> TraceEvent:
        self._counter += 1
        event = TraceEvent(
            event_id=f"evt-{self._counter:05d}",
            event_type=event_type,
            turn=turn,
            node_id=node_id,
            related_ids=tuple(related_ids),
            summary=compact_summary(summary),
            payload_digest=digest(payload) if payload is not None else None,
            data=data or {},
        )
        self.events.append(event)
        return event

    def to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                **asdict(event),
                "event_type": event.event_type.value,
            }
            for event in self.events
        ]

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

