"""Host-side adapter from persistent state events to version evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .authorization_dag import DagDecision
from .authorization_runtime import AuthorizationRuntime
from .versioned_evidence import StateVersion


@dataclass(frozen=True)
class StateChangeEvidence:
    object_id: str
    before_version_id: str | None
    after_version_id: str
    created_by_call_id: str
    write_authorized: bool | None


class PersistentStateMonitor:
    """Maintain immutable state lineage from host-observed reads and writes.

    The monitor does not infer authorization.  It records the decision made by
    the authorization runtime at write time: ALLOW becomes ``True``, ALERT
    becomes ``False``, and REVIEW remains unknown.  Initial workspace content
    is trusted only when ``trust_initial_state`` is enabled by the deployment
    threat model.
    """

    def __init__(self, runtime: AuthorizationRuntime, *,
                 trust_initial_state: bool = True) -> None:
        self.runtime = runtime
        self.trust_initial_state = trust_initial_state

    @staticmethod
    def authorization_value(decision: DagDecision) -> bool | None:
        return True if decision.verdict == "allow" else (
            False if decision.verdict == "alert" else None
        )

    def record_change(self, *, object_id: str,
                      before_version_id: str | None,
                      after_version_id: str,
                      created_by_call_id: str,
                      value: Any,
                      decision: DagDecision) -> StateChangeEvidence:
        if before_version_id is not None and not self.runtime.version_ledger.contains(
                object_id, before_version_id):
            self.runtime.version_ledger.record(StateVersion(
                object_id=object_id,
                version_id=before_version_id,
                parent_version_id=None,
                created_by_call_id=None,
                value=None,
                write_authorized=True if self.trust_initial_state else None,
            ))
        authorized = self.authorization_value(decision)
        if not self.runtime.version_ledger.contains(object_id, after_version_id):
            self.runtime.record_state_version(
                object_id=object_id,
                version_id=after_version_id,
                parent_version_id=before_version_id,
                created_by_call_id=created_by_call_id,
                value=value,
                write_authorized=authorized,
            )
        return StateChangeEvidence(
            object_id, before_version_id, after_version_id,
            created_by_call_id, authorized,
        )

    def record_read(self, *, call_id: str, tool: str, object_id: str,
                    version_id: str, value: Any,
                    arguments: dict[str, Any] | None = None) -> None:
        if not self.runtime.version_ledger.contains(object_id, version_id):
            self.runtime.version_ledger.record(StateVersion(
                object_id=object_id,
                version_id=version_id,
                parent_version_id=None,
                created_by_call_id=None,
                value=value,
                write_authorized=True if self.trust_initial_state else None,
            ))
        self.runtime.observe_tool_result(
            call_id, tool, value, arguments=arguments,
            object_id=object_id, version_id=version_id,
        )
