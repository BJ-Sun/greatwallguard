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

- 已形成可直接接入 Agent 工具网关的 Programmatic Core v0.1；
- 已在 570 条轨迹、5,674 次工具调用上完成回归，模块化前后判定差异为 0；
- 258 条具有明确目标调用的攻击中，63 条高置信告警，195 条进入复核；
- 265 条正常任务中没有高置信误报，79 条进入复核；
- 当前重点是降低 `REVIEW` 中的正常任务比例，而不是继续堆叠正则规则。

## 快速使用

```python
from greatwallguard import ProgrammaticAuthorizationGuard

guard = ProgrammaticAuthorizationGuard()
guard.on_user_message(user_text, turn=turn, trusted=True)

decision = guard.before_tool_call(
    tool_name,
    arguments,
    turn=turn,
    call_id=call_id,
)

guard.after_tool_result(call_id, succeeded=not tool_error)
```

- `allow`：调用与尚未消费的明确授权一致；
- `alert`：没有对应授权，或关键参数明确冲突；
- `review`：工具影响、参数来源或授权语义仍不充分。

完整接口、状态恢复和适配原则见 [Programmatic Core v0.1](docs/PROGRAMMATIC_GUARD_MODULE.md)。

## 文档索引

### 1. 新成员首先阅读

1. [方法总览与协作入口](docs/METHOD_OVERVIEW_AND_HANDOFF.md)：研究问题、方法边界、相关工作定位、实验结论与任务分工。
2. [Programmatic Core v0.1](docs/PROGRAMMATIC_GUARD_MODULE.md)：可直接使用的程序接口和跨 benchmark 适配规则。
3. [任务内持久状态的效果授权](docs/AUTHORIZATION_AND_EXECUTION_GRAPH_V1.md)：论文问题、威胁模型和状态版本研究主线。

### 2. 当前程序化检测实验

- [AgentDojo 小规模固定轨迹实验](docs/AGENTDOJO_PROGRAMMATIC_V01.md)：6组官方任务揭示同工具、动态参数场景中的误报边界。
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
| `src/greatwallguard/programmatic_guard.py` | 当前公开授权检查模块 |
| `src/greatwallguard/authorization_rules.py` | 结构化授权、账本和参数绑定原型 |
| `src/greatwallguard/native_openclaw_graph.py` | OpenClaw 原生事件建图 |
| `experiments/large_scale_authorization_v1.py` | 570 条轨迹回放 |
| `experiments/large_scale_authorization_v1_results.json` | 冻结逐 case 结果 |
| `experiments/large_scale_semantic_audit_v0.py` | REVIEW 样本的局部语义审计 |
| `tests/test_programmatic_guard.py` | 模块公开接口测试 |

## 运行测试

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:experiments \
python3 -m unittest discover -s tests -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:experiments \
python3 -m unittest discover -s experiments -p 'test_*.py'
```

当前仓库不保存 API Key。需要模型的实验应从环境变量读取凭据，不得写入代码、轨迹或实验报告。

## 下一步

保持 Programmatic Core v0.1 不变，优先接入 AgentDojo：先对固定轨迹测试跨数据集泛化，再进行少量真实重放。之后针对 `REVIEW` 分别补充授权提取、参数来源、状态版本和选择性 LLM 审计，并同时报告攻击检出、正常误报和审计成本。
