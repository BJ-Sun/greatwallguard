#!/usr/bin/env python3
"""Force the residual proof obligations to terminal ALLOW/DENY decisions."""

from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from greatwallguard import ProofPacketBuilder, TERMINAL_SYSTEM_PROMPT, TerminalAdjudication


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "experiments" / "stage3_proof_obligation"
OUT = ROOT / "experiments" / "stage3_terminal_adjudication"
RESULTS = OUT / "results.json"


def _client_class():
    path = ROOT / "experiments" / "stage3_audit_comparison.py"
    spec = importlib.util.spec_from_file_location("stage3_audit_comparison", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.DeepSeekJson, module._load_key


def _load_records() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    manifest = json.loads((PROOF / "manifest.json").read_text(encoding="utf-8"))["records"]
    prior = {row["record_id"]: row for row in json.loads(
        (PROOF / "results.json").read_text(encoding="utf-8")
    )["rows"]}
    return [row for row in manifest if prior[row["record_id"]]["final_verdict"] == "need_evidence"], prior


def run() -> dict[str, Any]:
    records, prior = _load_records()
    output = json.loads(RESULTS.read_text()) if RESULTS.exists() else {
        "schema": "greatwallguard-stage3-terminal-adjudication-results-v1", "rows": [],
    }
    done = {row["record_id"] for row in output["rows"]}
    Client, load_key = _client_class()
    client = Client(load_key())
    builder = ProofPacketBuilder(max_evidence_items=6)
    OUT.mkdir(parents=True, exist_ok=True)
    for index, record in enumerate(records, 1):
        if record["record_id"] in done:
            continue
        packet = builder.build(
            obligation_id=record["record_id"],
            trusted_user_request=record["trusted_user_request"],
            pending_call=record["pending_call"],
            review_reason=record["review_reason"],
            review_field=record.get("review_field"),
            execution_prefix=record["execution_prefix"],
            expand_all=True,
        )
        previous = prior[record["record_id"]]["attempts"][-1]["prediction"]
        body = packet.to_dict()
        body["prior_proof_attempt"] = {
            "missing_fact": previous.get("missing_fact"),
            "suggested_query": previous.get("suggested_query"),
            "rationale": previous.get("rationale"),
        }
        digest = hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
        prediction, usage = client.ask(TERMINAL_SYSTEM_PROMPT, body)
        decision = TerminalAdjudication.from_mapping(prediction)
        output["rows"].append({
            "record_id": record["record_id"], "benchmark": record["benchmark"],
            "group": record["group"], "suite": record["suite"],
            "packet_hash": digest, "decision": {
                "verdict": decision.verdict,
                "rationale": decision.rationale,
                "authorization_basis": decision.authorization_basis,
                "decisive_refs": list(decision.decisive_refs),
                "uncertainty": decision.uncertainty,
            },
            "usage": usage,
        })
        output["summary"] = _summarize(output["rows"])
        RESULTS.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if index % 20 == 0 or index == len(records):
            print(f"{index}/{len(records)}", flush=True)
    return output


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = Counter((r["benchmark"], r["group"], r["decision"]["verdict"]) for r in rows)
    return {
        "records": len(rows),
        "tokens": sum(int((r.get("usage") or {}).get("total_tokens") or 0) for r in rows),
        "outcomes": [
            {"benchmark": k[0], "group": k[1], "verdict": k[2], "count": v}
            for k, v in sorted(outcomes.items())
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run()["summary"], ensure_ascii=False, indent=2))
