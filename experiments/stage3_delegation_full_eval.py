#!/usr/bin/env python3
"""Full Stage-3 audit of semantic REVIEW calls after delegation typing."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import stage3_current_review_pilot as base


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "stage3_delegation_full"
MANIFEST = OUT / "manifest.json"
RESULT = OUT / "results.json"


def build_manifest() -> dict:
    records = []
    records.extend(base._extract_benchmark(
        "agentdojo", ROOT / "experiments" / "stage2_full" /
        "agentdojo_results_delegation_v1.json",
    ))
    records.extend(base._extract_benchmark(
        "agentdyn", ROOT / "experiments" / "stage2_delegation_v1" /
        "agentdyn_results.json",
    ))
    observations = base._normal_observations()
    for row in records:
        values = observations[(row["benchmark"], row["suite"], row["task_id"])]
        canonical_count = min(len(values), len(row["execution_prefix"]))
        for index in range(canonical_count):
            row["execution_prefix"][index]["observation"] = values[index]
        row["observation_coverage"] = {
            "canonical_prefix_calls": canonical_count,
            "prefix_calls": len(row["execution_prefix"]),
            "all_prefix_calls_observed": canonical_count == len(row["execution_prefix"]),
        }
    counts = Counter((row["benchmark"], row["group"], row["category"]) for row in records)
    output = {
        "schema": "greatwallguard-stage3-delegation-full-manifest-v1",
        "protocol": (
            "all call-level REVIEW decisions from typed Stage-2 full results; canonical mock "
            "observations re-executed locally; only semantic_unresolved enters LLM audit"
        ),
        "summary": [
            {"benchmark": key[0], "group": key[1], "category": key[2], "count": count}
            for key, count in sorted(counts.items())
        ],
        "records": records,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def _packet(row: dict) -> dict:
    return {
        "trusted_user_request": row["trusted_user_request"],
        "review_obligation": {
            "review_type": row["review_type"],
            "reason": row["review_reason"],
            "field": row["review_field"],
        },
        "execution_prefix": row["execution_prefix"],
        "pending_call": row["pending_call"],
    }


def summarize(rows: list[dict]) -> dict:
    counts = Counter((row["benchmark"], row["group"], row["prediction"]["verdict"])
                     for row in rows)
    return {
        "audited_calls": len(rows),
        "outcomes": [
            {"benchmark": key[0], "group": key[1], "verdict": key[2], "count": value}
            for key, value in sorted(counts.items())
        ],
        "normal_authorized": sum(
            row["group"] == "normal" and row["prediction"]["verdict"] == "authorized"
            for row in rows
        ),
        "normal_total": sum(row["group"] == "normal" for row in rows),
        "attack_unauthorized": sum(
            row["group"] == "attack" and row["prediction"]["verdict"] == "unauthorized"
            for row in rows
        ),
        "attack_false_allow": sum(
            row["group"] == "attack" and row["prediction"]["verdict"] == "authorized"
            for row in rows
        ),
        "attack_total": sum(row["group"] == "attack" for row in rows),
        # Cached rows retain the original usage for reproducibility, but did not
        # incur another API request and must not be double-counted.
        "tokens": sum(
            int((row.get("usage") or {}).get("total_tokens") or 0)
            for row in rows if not row.get("reused_prediction")
        ),
    }


def run() -> dict:
    manifest = build_manifest() if not MANIFEST.exists() else json.loads(MANIFEST.read_text())
    selected = [row for row in manifest["records"] if row["category"] == "semantic"]
    if RESULT.exists():
        output = json.loads(RESULT.read_text())
    else:
        output = {
            "schema": "greatwallguard-stage3-delegation-full-results-v1",
            "protocol": manifest["protocol"],
            "rows": [],
        }
    done = {row["record_id"] for row in output["rows"]}
    cached = {
        row["packet_hash"]: (row["prediction"], row.get("usage") or {})
        for row in output["rows"] if row.get("packet_hash")
    }
    Client, load_key = base._client_class()
    client = Client(load_key())
    for index, row in enumerate(selected, 1):
        if row["record_id"] in done:
            continue
        packet = _packet(row)
        packet_hash = hashlib.sha256(
            json.dumps(packet, ensure_ascii=False, sort_keys=True, default=str).encode()
        ).hexdigest()
        if packet_hash in cached:
            prediction, usage = cached[packet_hash]
            reused = True
        else:
            prediction, usage = client.ask(base.SYSTEM, packet)
            cached[packet_hash] = (prediction, usage)
            reused = False
        output["rows"].append({
            "record_id": row["record_id"], "benchmark": row["benchmark"],
            "group": row["group"], "suite": row["suite"],
            "review_reason": row["review_reason"], "review_field": row["review_field"],
            "expected": row["expected"], "prediction": prediction, "usage": usage,
            "packet_hash": packet_hash, "reused_prediction": reused,
        })
        RESULT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if index % 20 == 0 or index == len(selected):
            print(f"{index}/{len(selected)} semantic REVIEW calls", flush=True)
    output["summary"] = summarize(output["rows"])
    RESULT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build or run the full typed Stage-3 semantic audit.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Send semantic REVIEW packets to the configured audit API. Without this flag, only the local manifest is built.",
    )
    args = parser.parse_args()
    if args.run:
        result = run()
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
        return
    manifest = build_manifest()
    counts = Counter(
        (row["benchmark"], row["group"], row["category"])
        for row in manifest["records"]
    )
    print(json.dumps({
        "records": len(manifest["records"]),
        "semantic_api_calls": sum(
            value for key, value in counts.items() if key[2] == "semantic"
        ),
        "summary": [
            {"benchmark": key[0], "group": key[1], "category": key[2], "count": value}
            for key, value in sorted(counts.items())
        ],
        "note": "No external API was called. Pass --run explicitly to execute semantic audits.",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
