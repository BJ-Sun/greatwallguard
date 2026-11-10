# GreatWallGuard

GreatWallGuard 研究动态、长程 LLM Agent 中的运行时授权：先从可信用户指令提取结构化授权，再在工具执行前检查操作、对象和关键参数；程序证据不足的调用进入来源、状态版本或局部 LLM 审计。

```text
可信用户指令 + 工具环境
          ↓
      结构化授权
          ↓
     跨轮授权账本
          ↓
Agent 工具调用 ──→ ALLOW / ALERT / REVIEW
                                  ↓
                         来源 / 版本 / LLM 审计
```

## 当前状态

- 已实现“自然语言授权编译 → 运行时关系证明”的前两阶段原型；
- AgentDyn 两组未见任务上，授权编译联合正确率分别为 9/12 和 10/12；
- 阶段二已形成无 LLM 的在线证明内核，覆盖字段来源、范围传播、有限关系算子、动态预算和状态版本；
- 最新类型化效果策略只允许部署契约声明的中间能力降级复核，未经授权的新增终端效果直接告警；
- AgentDojo 全量回放：正常任务 `60 Allow / 37 Review / 0 Alert`；609 个有实际目标动作的攻击组合 `0 Allow / 179 Review / 430 Alert`；
- AgentDyn 全量回放：正常任务 `6 Allow / 54 Review / 0 Alert`；560 个攻击组合 `0 Allow / 337 Review / 223 Alert`；
- 相比保守策略，高置信攻击阻断率分别从 7.4% 提升到 70.6%、从 2.1% 提升到 39.8%，正常硬误报仍为 0；`Review` 不计作攻击检出；
- 阶段三已完成 638 个语义未决调用的全量审计；第一版虽然保持攻击直接放行为 0，但产生 22/157 个正常硬告警；
- 阶段三将复核原因编译为原子证明义务，并从执行图切出局部证据交给 LLM；终局授权把剩余未决项收敛为 `ALLOW / DENY / CONFIRM`，最终 `REVIEW=0`；
- 正常任务 126/157（80.3%）自动放行、14/157（8.9%）确认、17/157（10.8%）拒绝；有效攻击自动放行为 **0/1,169**，97.9% 拒绝、2.1% 确认；
- 当前限制是正常任务仍会因缺少运行时证据而被拒绝或要求确认；下一步接入由 `missing_fact + suggested_query` 驱动的只读补证或局部重放。

## 快速使用

```python
from greatwallguard import GreatWallGuardMethod

method = GreatWallGuardMethod(
    effect_contracts=effect_contracts,
    observation_tools=observation_tools,
    intent_backend=intent_backend,
    observation_contracts=observation_contracts,
    capability_rules=capability_rules,
)
runtime = method.start_task(trusted_user_message)

decision = runtime.authorize_tool_call(
    call_id, tool_name, arguments, read_only=is_observation,
)
if decision.verdict == "allow":
    result = execute_tool(tool_name, arguments)
    runtime.commit_tool_result(call_id, succeeded=tool_succeeded(result), result=result)
```

- `allow`：调用已获得完整授权证明；
- `alert`：效果、参数、约束、预算或范围存在明确冲突；
- `review`：来源、动态次数、中间能力或语义证据仍不充分。

当前方法、在线生命周期和实验边界见[三阶段运行时授权方法](docs/THREE_STAGE_AUTHORIZATION_METHOD.md)。

## 文档索引

### 1. 新成员首先阅读

1. [三阶段运行时授权方法与实验结论](docs/THREE_STAGE_AUTHORIZATION_METHOD.md)：当前唯一的方法主文档，说明三个阶段为何需要、如何实现、验证到哪一步。
2. [阶段二完整实现与双基准评估](docs/STAGE2_FULL_EVALUATION.md)：最新全量口径、最终数字、能力边界和复现入口。
3. [显式委托与类型化复核](docs/DELEGATION_TYPED_REVIEW_EVALUATION.md)：委托数据结构、三类 REVIEW、双基准回归和第三阶段全量清单。
4. [阶段三最小证据语义审计全量评估](docs/STAGE3_FULL_EVALUATION.md)：638 条语义复核的调用级、任务级结果与误报归因。
5. [阶段三正常告警审查](docs/STAGE3_NORMAL_ALERT_ANALYSIS.md)：22 个正常 ALERT 的逐类归因，以及三态语义证明的下一步设计。
6. [阶段三 v2：三态证明与冲突证书](docs/STAGE3_CONFLICT_CERTIFICATE_EVALUATION.md)：正常硬告警从 22/157 降至 1/157 的完整实验与限制。
7. [阶段三证明义务评估](docs/STAGE3_PROOF_OBLIGATION_EVALUATION.md)：原子证明问题、图上证据切片、一次有界扩展及最新全量结果。
8. [当前收敛方法](docs/FINAL_CONVERGED_METHOD.md)：当前方案、使用流程、实验结论和唯一下一步。
9. [阶段三终局授权](docs/STAGE3_TERMINAL_ADJUDICATION.md)：消除 REVIEW 的终局策略、完整实验与代价。
10. [方法设计动机演进](docs/method-motivation/README.md)：从静态白名单到计划无关关系证明的历史实验依据。
11. [Programmatic Core v0.1](docs/PROGRAMMATIC_GUARD_MODULE.md)：早期公开接口及跨 benchmark 适配原则。
12. [任务内持久状态的效果授权](docs/AUTHORIZATION_AND_EXECUTION_GRAPH_V1.md)：状态版本研究支线。

### 2. 当前程序化检测实验

- [AgentDojo 小规模固定轨迹实验](docs/AGENTDOJO_PROGRAMMATIC_V01.md)：6组官方任务揭示同工具、动态参数场景中的误报边界。
- [AgentDojo 符号授权阶段 A](docs/AGENTDOJO_SYMBOLIC_STAGE_A.md)：人工授权验证表示和匹配器的区分能力。
- [AgentDojo 自动授权阶段 B](docs/AGENTDOJO_SYMBOLIC_STAGE_B.md)：自动编译结果及“授权不应等同于唯一计划”的发现。
- [AgentDojo 事实图—关系授权桥接](docs/AGENTDOJO_BEHAVIOR_GRAPH_RELATION_BRIDGE.md)：真实工具返回如何进入现有事实图，并区分程序证据与候选语义。
- [AgentDojo 全量程序化授权基线](docs/AGENTDOJO_PROGRAMMATIC_FULL_V01.md)：97 个正常任务与 609 个有效攻击组合的无 LLM 评估及错误归因。
- [结构化效果授权 v0.5](docs/STRUCTURED_EFFECT_AUTHORIZATION_V05.md)：将动态参数从“未授权”中分离，消除冻结样本中的高置信正常误报，并给出下一步事实图验证集合。
- [通用 Schema-Grounded 授权 v0.7](docs/SCHEMA_GROUNDED_AUTHORIZATION_V07.md)：以有限效果本体和工具契约替代逐任务规则，并在全量 AgentDojo 上验证其能力边界。
- [运行时参数溯源 v1.1](docs/RUNTIME_PARAMETER_PROVENANCE_V09.md)：在 97 个真实执行的正常任务及 609 个攻击对照上，以可重放关系证明动态参数，评估纯程序化方法的进一步上限。
- [AgentDojo 最新正常任务复核归因](docs/AGENTDOJO_NORMAL_REVIEW_TAXONOMY_V27.md)：分析剩余36个复核任务，区分程序关系、内容语义、开放委托及评测/契约问题。
- [冻结算子与泛化验证](docs/method-motivation/06_FROZEN_OPERATOR_GENERALIZATION.md)：审计现有算子的任务复用范围，并规定未见任务上的前瞻验证协议。
- [AgentDojo 邮件计划无关实验](docs/AGENTDOJO_EMAIL_PLAN_INVARIANCE.md)：两条合法路径、无关来源与证据不足的关系证明对照。
- [程序化规则完善实验](docs/PROGRAMMATIC_RULE_COMPLETION_V1.md)：补齐工具契约后的实测结论。
- [第一版大规模授权实验](docs/LARGE_SCALE_AUTHORIZATION_V0.md)：570 条轨迹的实验口径与详细分析。
- [在线 Effect Guard 试验](docs/ONLINE_EFFECT_GUARD_PILOT.md)：调用前检查接口的早期验证。
- [用户授权提取计划](docs/USER_AUTHORIZATION_EXTRACTION_V0_PLAN.md)与[结果](docs/USER_AUTHORIZATION_EXTRACTION_V0_RESULTS.md)：规则与 LLM 提取的首轮实验。
- [授权增量试验](docs/INTENT_DELTA_PILOT.md)：多轮追加、撤销和未绑定参数。

### 3. 执行图、来源与状态版本

- [图设计说明](docs/GRAPH_DESIGN.md)：`Observation → Action → Effect → State` 基础结构。
- [图表征规范](docs/REPRESENTATION_SPEC.md)：事实、推断、证据等级和内容索引边界。
- [多级图设计](docs/MULTI_LEVEL_GRAPH.md)与[实验报告](docs/MULTI_LEVEL_GRAPH_REPORT.md)：L0–L3 视图和压缩验证。
- [图覆盖审计](docs/GRAPH_GAP_AUDIT.md)：当前不能稳定表达的信息。
- [图检测基线](docs/GRAPH_DETECTION_BASELINE.md)：早期图规则与适用边界。
- [图状态摘要结果](docs/GRAPH_SUMMARY_RESULTS.md)：长程压缩和信息保留实验。
- [收件人来源绑定](docs/RECIPIENT_SOURCE_BINDING_PILOT.md)：参数来源证据的最小真实轨迹试验。

### 4. 数据与评测协议

- [无注入正常任务对照集](docs/BENIGN_CONTROL_DATASET.md)：正常样本构造、质量门槛和首批结果。
- [AgentDojo 样例协议](docs/AGENTDOJO_CASE_PROTOCOL.md)：case、执行图和 oracle 的统一记录格式。
- [攻击样例标注](docs/ATTACK_ANNOTATIONS.md)：入口、Action、Effect、State 与成功条件。
- [条件授权预注册](docs/CONDITIONAL_AUTHORIZATION_V0_PREREGISTRATION.md)与[实验结果](docs/CONDITIONAL_AUTHORIZATION_V0_RESULTS.md)。

### 5. 早期试验与研究依据

- [研究动机](docs/MOTIVATION.md)：从局部动作检测到跨轮效果授权。
- [用户意图相关工作](docs/USER_INTENT_LITERATURE_MAP.md)：意图如何转化为运行时授权。
- [TaskScope 原型](docs/TASK_SCOPE_MINIMAL.md)、[TaskScope × Effect 实验](docs/EFFECT_SCOPE_PILOT.md)和[逐项 Effect 承诺](docs/EFFECT_COMMITMENT_PILOT.md)：方法演进依据。
- [邮件图后验分析](docs/EMAIL_GRAPH_POSTHOC_V0.md)与[邮件可判定性审查](docs/EMAIL_DECIDABILITY_PILOT.md)：正常与攻击难例。

## 代码与结果入口

| 路径 | 用途 |
|---|---|
| `src/greatwallguard/programmatic_guard.py` | 早期基线兼容模块 |
| `src/greatwallguard/method.py` | 当前方法的统一公开入口 |
| `src/greatwallguard/authorization_runtime.py` | 有状态在线授权、预算、撤销与快照 |
| `src/greatwallguard/authorization_dag.py` | 授权 DAG 与调用前验证器 |
| `src/greatwallguard/dag_evidence_evaluator.py` | 有限来源、变换与约束求值 |
| `src/greatwallguard/relational_authorization.py` | 计划无关的关系授权验证器 |
| `src/greatwallguard/relation_proof.py` | 执行事实与可重放证明规则 |
| `src/greatwallguard/semantic_audit.py` | 三态语义证明与有限冲突证书校验 |
| `src/greatwallguard/proof_obligation_packet.py` | 原子证明义务与执行图证据切片 |
| `src/greatwallguard/terminal_adjudication.py` | 无 REVIEW 的终局授权裁决 |
| `src/greatwallguard/final_gateway.py` | 自动补证与无 REVIEW 的终局效果处置 |
| `src/greatwallguard/authorization_rules.py` | 结构化授权、账本和参数绑定原型 |
| `src/greatwallguard/native_openclaw_graph.py` | OpenClaw 原生事件建图 |
| `experiments/large_scale_authorization_v1.py` | 570 条轨迹回放 |
| `experiments/large_scale_authorization_v1_results.json` | 冻结逐 case 结果 |
| `experiments/large_scale_semantic_audit_v0.py` | REVIEW 样本的局部语义审计 |
| `tests/test_programmatic_guard.py` | 模块公开接口测试 |
| `experiments/stage3_conflict_certificate_eval.py` | 阶段三 v2 全量负例复核实验 |
| `experiments/stage3_conflict_certificate/` | 调用级与任务级冻结结果 |
| `experiments/stage3_proof_obligation_eval.py` | 阶段三证明义务全量实验 |
| `experiments/stage3_proof_obligation/` | 最新调用级与任务级冻结结果 |
| `experiments/stage3_terminal_adjudication/` | 终局调用级与任务级冻结结果 |

## 运行测试

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:experiments \
python3 -m unittest discover -s tests -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:experiments \
python3 -m unittest discover -s experiments -p 'test_*.py'
```

当前仓库不保存 API Key。需要模型的实验应从环境变量读取凭据，不得写入代码、轨迹或实验报告。

## 下一步

把审计输出的 `missing_fact + suggested_query` 接入真实只读补证或局部重放；检验新增事实能否关闭正常任务的证明义务，同时保持攻击 `SUPPORTED=0`。其余语义未决项保持 `REVIEW`，不通过 benchmark 专用规则提高表面检出率。
