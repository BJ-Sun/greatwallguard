"""Time-ordered maintenance of authorization DAGs across trusted user turns."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from typing import Iterable

from .authorization_dag import AuthorizationDAG, AuthorizationEdge, AuthorizationNode
from .authorization_runtime import AuthorizationRuntime


@dataclass(frozen=True)
class AuthorizationUpdateRecord:
    turn: int
    namespace: str
    message_sha256: str
    added_effect_ids: tuple[str, ...]
    revoked_effect_ids: tuple[str, ...]


def merge_authorization_dag(base: AuthorizationDAG, delta: AuthorizationDAG, *,
                            namespace: str) -> tuple[str, ...]:
    """Merge one independently validated turn DAG under a collision-free prefix."""
    if not namespace or any(char.isspace() for char in namespace):
        raise ValueError("authorization namespace must be non-empty and whitespace-free")
    mapping = {node_id: f"{namespace}/{node_id}" for node_id in delta.nodes}
    for node in delta.nodes.values():
        attrs = dict(node.attrs)
        if node.kind == "effect" and "grant_id" in attrs:
            attrs["grant_id"] = f"{namespace}/{attrs['grant_id']}"
        base.add_node(AuthorizationNode(
            id=mapping[node.id], kind=node.kind, value_type=node.value_type,
            op=node.op, attrs=attrs, status=node.status,
        ))
    for edge in delta.edges:
        base.add_edge(AuthorizationEdge(
            mapping[edge.source], mapping[edge.target], edge.kind, dict(edge.attrs),
        ))
    for grant in delta.delegations:
        base.delegations = (*base.delegations, replace(
            grant, delegation_id=f"{namespace}/{grant.delegation_id}",
        ))
    base.delegated = base.delegated or delta.delegated
    return tuple(
        mapping[node.id] for node in delta.nodes.values() if node.kind == "effect"
    )


class AuthorizationTimeline:
    """Apply trusted turns before later calls and preserve their authorization epoch."""

    def __init__(self, runtime: AuthorizationRuntime) -> None:
        self.runtime = runtime
        self.records: list[AuthorizationUpdateRecord] = []
        if "trusted_user_intent" not in runtime.graph.nodes:
            runtime.graph.add_node(AuthorizationNode(
                "trusted_user_intent", "source", "TrustedUserMessage",
                attrs={"source_type": "trusted_user", "text": ""},
                status="proved",
            ))

    def apply(self, *, turn: int, trusted_message: str,
              delta: AuthorizationDAG,
              revoke_effect_ids: Iterable[str] = (),
              supersede_same_tools: bool = True) -> AuthorizationUpdateRecord:
        if self.records and turn <= self.records[-1].turn:
            raise ValueError("trusted authorization turns must be strictly increasing")
        namespace = f"turn-{turn}"
        revoked = list(revoke_effect_ids)
        if supersede_same_tools:
            delta_tools = {
                str(node.attrs.get("tool")) for node in delta.nodes.values()
                if node.kind == "effect" and node.attrs.get("tool")
            }
            revoked.extend(
                node.id for node in self.runtime.graph.nodes.values()
                if node.kind == "effect"
                and node.attrs.get("tool") in delta_tools
                and node.id not in self.runtime.revoked
            )
        added = merge_authorization_dag(
            self.runtime.graph, delta, namespace=namespace,
        )
        applied_revocations = []
        for effect_id in dict.fromkeys(revoked):
            self.runtime.revoke(effect_id)
            applied_revocations.append(effect_id)
        self.runtime.resolver.extend_trusted_message(trusted_message)
        self.runtime.user_message = self.runtime.resolver.user_message
        self.runtime.graph.nodes["trusted_user_intent"].attrs["text"] = (
            self.runtime.user_message
        )
        record = AuthorizationUpdateRecord(
            turn=turn, namespace=namespace,
            message_sha256=hashlib.sha256(trusted_message.encode()).hexdigest(),
            added_effect_ids=added, revoked_effect_ids=tuple(applied_revocations),
        )
        self.records.append(record)
        return record
