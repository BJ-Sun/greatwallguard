#!/usr/bin/env python3
"""Offline smoke example for the deployable v0.1 interfaces."""

from greatwallguard import (
    CallableEvidenceResolver,
    GreatWallGuardMethod,
    JsonProofAuditor,
    JsonTerminalAuditor,
    ProofObligation,
    ProofPacket,
)


def fake_model(system_prompt, payload):
    if "atomic authorization proof" in system_prompt:
        return {
            "verdict": "SUPPORTED",
            "rationale": "The trusted request contains the exact recipient.",
            "missing_fact": "",
            "suggested_query": None,
            "conflict_certificate": None,
        }
    return {
        "verdict": "ALLOW",
        "rationale": "Exact recipient is authorized.",
        "authorization_basis": "explicit_goal",
        "decisive_refs": ["trusted_user_request", "pending_call"],
        "uncertainty": "",
    }


def fetch_evidence(query, packet):
    return None


proof = JsonProofAuditor(fake_model)
terminal = JsonTerminalAuditor(fake_model)
resolver = CallableEvidenceResolver(fetch_evidence)
pipeline = GreatWallGuardMethod.build_terminal_pipeline(
    proof_auditor=proof,
    evidence_resolver=resolver,
    terminal_auditor=terminal,
)

packet = ProofPacket(
    trusted_user_request="Send the report to alice@example.com.",
    authorized_effect="send_email",
    candidate_call={
        "tool": "send_email",
        "arguments": {"recipients": ["alice@example.com"], "body": "Report"},
    },
    obligation=ProofObligation(
        "demo:1", "parameter_binding", "authorized_binding", "recipients",
        ["alice@example.com"], "Is the recipient authorized?",
    ),
    evidence=(),
)

decision = pipeline.resolve(stage2_verdict="review", packet=packet)
print({"disposition": decision.disposition.value, "reason": decision.reason})
assert decision.disposition.value == "allow"
