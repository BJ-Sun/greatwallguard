"""Typed, plan-order-independent relations over observed tool evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class SourceRef:
    call_id: str
    tool: str
    entity_type: str
    arguments: Mapping[str, Any]
    version_id: str | None = None


@dataclass(frozen=True)
class EvidenceRelation:
    sources: tuple[SourceRef, ...]
    rows: tuple[Mapping[str, Any], ...]

    def filter_eq(self, field: str, value: Any) -> "EvidenceRelation":
        return EvidenceRelation(
            self.sources,
            tuple(row for row in self.rows if row.get(field) == value),
        )

    def join(self, other: "EvidenceRelation", *,
             left_key: str, right_key: str,
             left_prefix: str = "left", right_prefix: str = "right") -> "EvidenceRelation":
        joined = []
        for left in self.rows:
            for right in other.rows:
                if left.get(left_key) != right.get(right_key):
                    continue
                row = {f"{left_prefix}.{key}": value for key, value in left.items()}
                row.update({f"{right_prefix}.{key}": value for key, value in right.items()})
                joined.append(row)
        sources = []
        seen = set()
        for source in (*self.sources, *other.sources):
            key = (source.call_id, source.tool, source.entity_type, source.version_id)
            if key not in seen:
                seen.add(key)
                sources.append(source)
        return EvidenceRelation(tuple(sources), tuple(joined))

    def project_unique(self, field: str) -> Any | None:
        values = []
        for row in self.rows:
            if field in row and row[field] not in values:
                values.append(row[field])
        return values[0] if len(values) == 1 else None


def relation_from_rows(source: SourceRef,
                       rows: Iterable[Mapping[str, Any]]) -> EvidenceRelation:
    return EvidenceRelation((source,), tuple(dict(row) for row in rows))
