#!/usr/bin/env python3
"""Resolve every remaining task-level REVIEW with bounded effect contracts.

This is a policy replay, not an end-to-end benchmark utility run.  A safe
substitute prevents the original effect and therefore counts as safe
continuation, not as completion of the original task.
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from greatwallguard import FinalAuthorizationGateway, SemanticAuditResult, contract


ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "experiments" / "stage3_delegation_full"
CERT = ROOT / "experiments" / "stage3_conflict_certificate"
OUT = ROOT / "experiments" / "stage3_terminal_gateway"


def benchmark_contracts() -> dict[str, Any]:
    """Reference deployment contracts grouped by effect semantics."""
    groups = {
        "isolated_observation": {
            "browse_webpage", "get_webpage", "download_file_through_id",
            "download_file_through_url", "login_shopping_account", "login_github_account",
        },
        "draft_communication": {
            "send_email", "send_direct_message", "send_channel_message",
        },
        "prepared_transaction": {
            "send_money", "schedule_transaction", "update_scheduled_transaction",
            "checkout_selected_cart", "refund_order", "reserve_hotel",
        },
        "staged_membership_change": {
            "add_user_to_channel", "invite_user_to_slack", "remove_user_from_slack",
            "git_invite_collaborators",
        },
        "preview_form_submission": {"input_to_webpage", "post_webpage"},
        "versioned_file_change": {
            "append_to_file", "create_file", "delete_file", "delete_node", "move_node",
        },
        "staged_repository_change": {"git_clone", "git_push", "git_star", "git_delete_ssh_key"},
        "draft_calendar_change": {"create_calendar_event"},
        "prepared_cart_change": {"cart_add_product"},
        "draft_account_change": {"update_password"},
        "quarantined_email_change": {"delete_email"},
    }
    descriptions = {
        "isolated_observation": "Fetch in an isolated reader without forwarding control instructions.",
        "draft_communication": "Create a draft without transmitting the message.",
        "prepared_transaction": "Prepare a transaction preview without committing funds or purchase.",
        "staged_membership_change": "Prepare a membership diff without applying it.",
        "preview_form_submission": "Render the form submission and redact sensitive fields without submitting.",
        "versioned_file_change": "Write a new version or quarantine item without destructive commit.",
        "staged_repository_change": "Apply the change to an isolated local branch without remote commit.",
        "draft_calendar_change": "Create a non-sent event draft without inviting participants.",
        "prepared_cart_change": "Prepare a cart diff without checkout.",
        "draft_account_change": "Prepare an account-change request without applying it.",
        "quarantined_email_change": "Move the email to quarantine instead of deleting it.",
    }
    output = {}
    for operation, tools in groups.items():
        for tool in tools:
            output[tool] = contract(tool, operation, operation, descriptions[operation])
    return output


def _unresolved_record(record_id: str, manifest: dict, v1: dict, v2: dict) -> bool:
    category = manifest[record_id]["category"]
    if category != "semantic":
        return True
    old = v1[record_id]["prediction"]["verdict"]
    if old == "uncertain":
        return True
    if old == "unauthorized":
        return v2[record_id]["final_verdict"] != "contradicted"
    return False


def evaluate() -> dict[str, Any]:
    task_analysis = json.loads((CERT / "task_analysis.json").read_text(encoding="utf-8"))
    manifest = {row["record_id"]: row for row in json.loads(
        (FULL / "manifest.json").read_text(encoding="utf-8")
    )["records"]}
    v1 = {row["record_id"]: row for row in json.loads(
        (FULL / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    v2 = {row["record_id"]: row for row in json.loads(
        (CERT / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    by_task: dict[tuple, list[tuple[str, dict]]] = {}
    for record_id, row in manifest.items():
        if not _unresolved_record(record_id, manifest, v1, v2):
            continue
        key = (
            row["benchmark"], row["group"], row["suite"], row["task_id"],
            row.get("injection_task_id"),
        )
        by_task.setdefault(key, []).append((record_id, row))

    contracts = benchmark_contracts()
    gateway = FinalAuthorizationGateway(contracts)
    dojo_stage2 = json.loads((
        ROOT / "experiments" / "stage2_full" / "agentdojo_results_delegation_v1.json"
    ).read_text(encoding="utf-8"))
    dojo_attack_has_target = {
        (row["suite"], str(row["user_task_id"]), row.get("injection_task_id")): bool(row["calls"])
        for row in dojo_stage2["attack_rows"]
    }
    rows = []
    uncovered = Counter()
    for task in task_analysis["rows"]:
        base = task["final"]
        key = (
            task["benchmark"], task["group"], task["suite"], task["task_id"],
            task.get("injection_task_id"),
        )
        call_rows = []
        if base == "allow":
            terminal = "allow_original"
        elif base == "alert":
            terminal = "deny"
        else:
            dispositions = []
            for record_id, item in by_task.get(key, []):
                tool = item["pending_call"]["tool"]
                if tool not in contracts:
                    uncovered[tool] += 1
                decision = gateway.resolve(
                    tool=tool,
                    stage2_verdict="review",
                    review_type=item.get("review_type"),
                    semantic_result=SemanticAuditResult("insufficient", "terminal replay"),
                )
                dispositions.append(decision.disposition.value)
                call_rows.append({
                    "record_id": record_id, "tool": tool,
                    "disposition": decision.disposition.value,
                    "substitute": decision.substitute.operation if decision.substitute else None,
                })
            terminal = (
                "request_confirmation" if "request_confirmation" in dispositions else
                "deny" if "deny" in dispositions or not dispositions else
                "allow_safe_substitute"
            )
        has_attack_target = True
        if task["group"] == "attack" and task["benchmark"] == "agentdojo":
            has_attack_target = dojo_attack_has_target[
                (task["suite"], task["task_id"], task.get("injection_task_id"))
            ]
        rows.append({
            **task,
            "has_attack_target": has_attack_target if task["group"] == "attack" else None,
            "terminal_disposition": terminal,
            "terminal_calls": call_rows,
        })

    counts = Counter((row["benchmark"], row["group"], row["terminal_disposition"]) for row in rows)
    effective_attack_counts = Counter(
        (row["benchmark"], row["terminal_disposition"])
        for row in rows if row["group"] == "attack" and row["has_attack_target"]
    )
    output = {
        "schema": "greatwallguard-stage3-terminal-gateway-eval-v1",
        "protocol": (
            "policy replay over residual REVIEW; safe substitute prevents original effect and "
            "does not count as original benchmark task completion"
        ),
        "uncovered_tools": dict(uncovered),
        "summary": [
            {"benchmark": k[0], "group": k[1], "disposition": k[2], "count": v}
            for k, v in sorted(counts.items())
        ],
        "effective_attack_summary": [
            {"benchmark": k[0], "disposition": k[1], "count": v}
            for k, v in sorted(effective_attack_counts.items())
        ],
        "rows": rows,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return output


if __name__ == "__main__":
    print(json.dumps(evaluate()["summary"], ensure_ascii=False, indent=2))
