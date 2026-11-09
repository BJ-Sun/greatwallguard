#!/usr/bin/env python3
"""Recompile AgentDyn and rerun Stage 2 with typed delegation IR."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import stage2_full_benchmark as stage2
from greatwallguard import (
    AuthorizationDAG, AuthorizationEdge, AuthorizationNode,
    infer_explicit_delegations,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "stage2_delegation_v1"


def configure() -> None:
    stage2.AGENTDYN_CACHE = OUT / "agentdyn_authorizations"
    stage2.AGENTDYN_RESULT = OUT / "agentdyn_results.json"


def migrate_cached_authorizations() -> dict[str, int]:
    source_root = ROOT / "experiments" / "stage2_full" / "agentdyn_authorizations_v2"
    destination_root = OUT / "agentdyn_authorizations"
    counts = {"migrated": 0, "delegated": 0}
    for source in sorted(source_root.glob("*/*.json")):
        payload = json.loads(source.read_text(encoding="utf-8"))
        if payload.get("status") == "compiled":
            graph = AuthorizationDAG.from_dict(payload["authorization_dag"])
            delegations = infer_explicit_delegations(str(payload.get("prompt", "")))
            if delegations:
                migrated = AuthorizationDAG(
                    version=graph.version + ":delegation-v1",
                    delegated=graph.delegated,
                    delegations=delegations,
                )
                for node in graph.nodes.values():
                    migrated.add_node(node)
                for edge in graph.edges:
                    migrated.add_edge(edge)
                for delegation in delegations:
                    if delegation.delegation_id in migrated.nodes:
                        continue
                    migrated.add_node(AuthorizationNode(
                        delegation.delegation_id, "delegation", "DelegatedAuthority",
                        attrs=delegation.to_dict(), status="proved",
                    ))
                    migrated.add_edge(AuthorizationEdge(
                        "trusted_user_intent", delegation.delegation_id, "delegates",
                        {"authority": delegation.authority},
                    ))
                graph = migrated
                counts["delegated"] += 1
            payload["authorization_dag"] = graph.to_dict()
            payload["migration"] = "deterministic-explicit-delegation-v1"
        destination = destination_root / source.parent.name / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        counts["migrated"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("compile", "migrate", "evaluate"))
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--retry-errors", action="store_true")
    args = parser.parse_args()
    configure()
    if args.command == "compile":
        result = stage2.compile_agentdyn(
            model=args.model, retry_errors=args.retry_errors,
        )
    elif args.command == "migrate":
        result = migrate_cached_authorizations()
    else:
        result = stage2.evaluate_agentdyn()["summary"]
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
