"""Project a previously recorded real AgentLAB execution into graph levels.

This is an offline validation path for environments where the model API is
temporarily unavailable.  It never invents agent actions: the input must be a
saved ``real_normal_validation.json`` produced by the online runner.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from greatwallguard.multi_level_graph import build_multi_level_graph


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    projected = build_multi_level_graph(payload["graph"])
    result = {
        "validation_kind": "offline_projection_of_saved_real_agent_execution",
        "source": str(args.input),
        "created_at": payload.get("created_at"),
        "model": payload.get("model"),
        "source_sessions": len(payload.get("sessions", [])),
        "source_final_metrics": payload.get("final_metrics", {}),
        "multi_level_graph": projected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "source_sessions": result["source_sessions"],
        "bytes": projected["meta"]["bytes"],
        "compression_ratio": projected["meta"]["compression_ratio"],
        "l2_objects": projected["levels"]["l2"]["object_count"],
        "l2_activations": projected["levels"]["l2"]["activation_count"],
        "l3_alerts": projected["meta"]["l3_alerts"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
