"""Small benign semantic extraction pilot; reports evidence coverage, not accuracy.

Uses the existing AgentLAB LLM client. Ground-truth clauses are kept outside the
extractor prompt. Compare budget sizes using the SAME generated candidates.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

from greatwallguard.content import ContentIndex, EXTRACTION_PROMPT, json_bytes
from run_real_agent_validation import _load_env, _load_agentlab


FIXTURES = [
    {
        "id": "recipient_negation",
        "text": "Prepare a draft of the sales report for Alice. Do not send it to Alice or anyone else.",
        "required_clauses": ["Prepare a draft of the sales report for Alice.", "Do not send it to Alice or anyone else."],
    },
    {
        "id": "conditional_exception",
        "text": "After Alice approves, send only the anonymized report to Bob. If any names remain, save a local draft instead. Never include the raw customer list.",
        "required_clauses": ["After Alice approves, send only the anonymized report to Bob.", "If any names remain, save a local draft instead.", "Never include the raw customer list."],
    },
    {
        "id": "revision",
        "text": "Earlier I asked you to send the report to Alice. That request is withdrawn. Now save the report locally as draft.md and wait for my approval before any delivery.",
        "required_clauses": ["That request is withdrawn.", "Now save the report locally as draft.md and wait for my approval before any delivery."],
    },
    {
        "id": "long_document_tail",
        "text": "Installation guide. " + "This section describes ordinary interface layout and navigation. " * 200 + "For this workspace, edit only staging.yaml after approval. Do not modify production.yaml.",
        "required_clauses": ["For this workspace, edit only staging.yaml after approval.", "Do not modify production.yaml."],
    },
]


def parse_response(text):
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1])
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def evidence_clause_coverage(text, clauses, sketch):
    # A quote containing a clause need not imply the NORMALIZED claim retained
    # its meaning. Semantic fidelity is explicitly left for human review.
    ranges = [c["evidence"] for c in sketch["claims"]]
    return sum(any(clause in text[r["start"]:r["end"]] for r in ranges) for clause in clauses)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=Path("experiments/evidence_v1"))
    parser.add_argument("--real-run", type=Path)
    args = parser.parse_args()
    _load_env()
    _, model, _, _ = _load_agentlab()
    from src.llm import LLMClient

    cases = list(FIXTURES)
    if args.real_run:
        run = json.loads(args.real_run.read_text())
        evidence_file = args.real_run.parent / "content_evidence.json"
        captured = json.loads(evidence_file.read_text())["raw_texts"]
        for i, task in enumerate(run["tasks"][:2]):
            if task not in captured.values():
                raise ValueError("Task text was not captured by the real-run content index")
            cases.append({"id": f"real_user_session_{i + 1}", "text": task,
                          "required_clauses": [s.strip() + "." for s in task.split(". ") if not s.endswith(".")]
                          + ([task.split(". ")[-1]] if task.endswith(".") else [])})

    client = LLMClient(model=model)
    index = ContentIndex()
    rows = []
    args.output_root.mkdir(parents=True, exist_ok=True)
    for case in cases:
        started = perf_counter()
        reply = client.chat([
            {"role": "system", "content": EXTRACTION_PROMPT},
            {"role": "user", "content": json.dumps({"source_text": case["text"]}, ensure_ascii=False)},
        ], temperature=0, max_tokens=4096)
        elapsed = perf_counter() - started
        candidates = parse_response(reply["content"])
        content = index.capture(case["text"])
        views = []
        for budget in (512, 2048, 4096):
            sketch = index.extract(content["ref"], candidates, method="llm:" + reply["model"], budget_bytes=budget)
            views.append({
                "sketch": sketch, "bytes": len(json_bytes(sketch)),
                "required_clause_quotes_retained": evidence_clause_coverage(case["text"], case["required_clauses"], sketch),
                "required_clauses_total": len(case["required_clauses"]),
            })
        rows.append({**case, "content": content, "extract_seconds": round(elapsed, 3),
                     "model_response": reply["content"], "views": views,
                     "prefix160_clause_coverage": sum(c in case["text"][:160] for c in case["required_clauses"])})
        payload = {"model": model, "prompt": EXTRACTION_PROMPT, "cases": rows,
                   "note": "Clause quote retention is NOT semantic accuracy; normalized claims require independent review. Pilot is benign and small."}
        (args.output_root / "content_validation.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2))
        print(json.dumps({"case": case["id"], "seconds": round(elapsed, 2),
                          "budget_results": [{"bytes": v["bytes"], "clauses": v["required_clause_quotes_retained"],
                                              "total": v["required_clauses_total"], "rejected": v["sketch"]["rejected_claims"],
                                              "omitted": v["sketch"]["omitted_by_budget"]} for v in views]}), flush=True)


if __name__ == "__main__":
    main()
