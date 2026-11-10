# 固定文件清单

## 核心模块

- `src/greatwallguard/method.py`
- `src/greatwallguard/authorization_dag.py`
- `src/greatwallguard/authorization_runtime.py`
- `src/greatwallguard/dag_evidence_evaluator.py`
- `src/greatwallguard/proof_obligation_packet.py`
- `src/greatwallguard/semantic_audit.py`
- `src/greatwallguard/terminal_adjudication.py`
- `src/greatwallguard/unified_authorization.py`
- `src/greatwallguard/dynamic_delegation.py`
- `src/greatwallguard/deployment_adapters.py`

## 结果来源

- 阶段二：`experiments/stage2_full/`
- 证明义务：`experiments/stage3_proof_obligation/`
- 终局裁决：`experiments/stage3_terminal_adjudication/`
- 动态委托：`experiments/dynamic_delegation_pilot/`

## 正式文档

- `docs/FINAL_CONVERGED_METHOD.md`
- `docs/STAGE3_PROOF_OBLIGATION_EVALUATION.md`
- `docs/STAGE3_TERMINAL_ADJUDICATION.md`
- `docs/NORMAL_FALSE_POSITIVE_GAP_AND_UNIFIED_PIPELINE.md`

历史实验文件不属于交付 API，不应被新适配器直接导入。
