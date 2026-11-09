"""Version-aware evidence primitives for persistent Agent state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import Mapping


@dataclass(frozen=True)
class StateVersion:
    object_id: str
    version_id: str
    parent_version_id: str | None
    created_by_call_id: str | None
    value: Any
    write_authorized: bool | None


@dataclass(frozen=True)
class VersionProof:
    object_id: str
    version_id: str
    chain: tuple[str, ...]
    verdict: str
    reason: str


class VersionLedger:
    """Record version lineage and prove whether a used version has an authorized chain."""

    def __init__(self) -> None:
        self._versions: dict[tuple[str, str], StateVersion] = {}

    def record(self, version: StateVersion) -> None:
        key = (version.object_id, version.version_id)
        if key in self._versions:
            raise ValueError(f"duplicate state version: {key}")
        if version.parent_version_id is not None:
            parent = (version.object_id, version.parent_version_id)
            if parent not in self._versions:
                raise ValueError(f"unknown parent version: {parent}")
        self._versions[key] = version

    def prove_usable(self, object_id: str, version_id: str) -> VersionProof:
        chain = []
        current = self._versions.get((object_id, version_id))
        if current is None:
            return VersionProof(object_id, version_id, (), "review", "unknown_version")
        seen = set()
        while current is not None:
            key = (current.object_id, current.version_id)
            if key in seen:
                return VersionProof(object_id, version_id, tuple(chain),
                                    "review", "version_cycle")
            seen.add(key)
            chain.append(current.version_id)
            if current.write_authorized is False:
                return VersionProof(object_id, version_id, tuple(chain),
                                    "alert", "unauthorized_version_in_lineage")
            if current.write_authorized is None:
                return VersionProof(object_id, version_id, tuple(chain),
                                    "review", "unresolved_write_authorization")
            if current.parent_version_id is None:
                break
            current = self._versions.get((object_id, current.parent_version_id))
            if current is None:
                return VersionProof(object_id, version_id, tuple(chain),
                                    "review", "broken_version_lineage")
        return VersionProof(object_id, version_id, tuple(chain),
                            "allow", "authorized_version_lineage")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "greatwallguard-version-ledger-v1",
            "versions": [
                {
                    "object_id": item.object_id,
                    "version_id": item.version_id,
                    "parent_version_id": item.parent_version_id,
                    "created_by_call_id": item.created_by_call_id,
                    "value": item.value,
                    "write_authorized": item.write_authorized,
                }
                for item in self._versions.values()
            ],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VersionLedger":
        if value.get("schema") != "greatwallguard-version-ledger-v1":
            raise ValueError("unsupported version ledger snapshot")
        ledger = cls()
        pending = [dict(item) for item in value.get("versions", [])]
        while pending:
            deferred = []
            progressed = False
            for item in pending:
                parent = item.get("parent_version_id")
                key = (str(item.get("object_id")), str(parent))
                if parent is not None and key not in ledger._versions:
                    deferred.append(item)
                    continue
                ledger.record(StateVersion(
                    object_id=str(item["object_id"]),
                    version_id=str(item["version_id"]),
                    parent_version_id=str(parent) if parent is not None else None,
                    created_by_call_id=(
                        str(item["created_by_call_id"])
                        if item.get("created_by_call_id") is not None else None
                    ),
                    value=item.get("value"),
                    write_authorized=item.get("write_authorized"),
                ))
                progressed = True
            if not progressed:
                raise ValueError("version ledger snapshot has broken lineage")
            pending = deferred
        return ledger
