# GreatWallGuard 当前进展

更新时间：2026-09-08

## 一句话结论

我们已经完成了 Agent 长程行为的第一版中立图表征和有界状态摘要验证，并完成
29 条已有攻击样例的 v0 标注、最小缺口审计、`effect_process_ledger` 和第一版图
检测基线。当前重点从“扩展基础图节点”转为“补过程/值流证据并做检测评估”。

## 已完成

### 1. 过程图 v0

- 固定四类节点：`Observation`、`Action`、`Effect`、`State`。
- 固定五类关系：`derived_from`、`causes`、`updates`、`reads`、`next`。
- 统一记录 `basis + method` 证据来源。
- 支持工具参数摘要、调用 ID、工具返回引用、状态版本和 SHA-256 指纹。
- 使用有限 Effect 词表，不把攻击语义写入基础图。

### 2. 有界状态摘要

`src/greatwallguard/state_summary.py` 已实现：

- `recent_trace`：保留最近过程事件；
- `effect_ledger`：保留活跃持久对象的最新版本和指纹；
- `content_sketch`：保留带证据的事实、约束、条件和修订。

支持 small / medium / large 三档预算，LLM 摘要失败时有确定性抽取式回退，并支持零 API 的确定性重放。

### 3. 真实正常任务验证

已使用真实 Agent 长时执行数据进行离线重建和压缩矩阵比较。`multifile` 任务包含 124 轮真实模型执行和自主工具调用：

| 视图 | 典型规模 | 主要特点 |
|---|---:|---|
| 完整图 + 原文 | 约 30MB | 信息最完整，但随轮次增长 |
| small 摘要 | 约 9KB | 压缩最高，内容覆盖有限 |
| medium 摘要 | 约 22–24KB | 内容覆盖和大小较平衡 |
| large 摘要 | 约 49–56KB | 覆盖较好，仍远小于完整图 |

在 turn 30：

- 三种摘要的持久状态覆盖率均为 100%；
- 固定滑动窗口的持久状态覆盖率为 0%；
- 摘要可从落盘图和缓存响应零 API 逐字节重建；
- 历史 `call_id` / 返回证据召回率较低，说明过程账本仍不完整。

### 4. 攻击样例与图审计 v0

- 选取 29 条已有 LONG/DOJO/AgentLAB/组合攻击样例，标注入口、关键 Action、持久
  Effect、State 传播和成功条件，并区分 `observed`、`declared`、`partial` 证据级别。
- 审计得到五项最小缺口：过程账本、值流/字段来源、复合 Effect/多目标、会话桥接与
  激活证据、结果 oracle 对齐；没有新增基础节点类型。
- 详见 [攻击样例标注表](ATTACK_ANNOTATIONS.md) 和 [图覆盖审计](GRAPH_GAP_AUDIT.md)。

### 5. 过程账本与检测基线

- `src/greatwallguard/effect_process_ledger.py` 已把持久 Effect 连接到 action、可选
  `call_id`、参数摘要、来源完整性、结果证据和 State 版本；失败/no-State Effect
  也保留。
- `src/greatwallguard/graph_detection.py` 已实现四类结构信号的无模型基线；详见
  [图检测基线](GRAPH_DETECTION_BASELINE.md)。
- 新增过程账本、call_id、检测基线测试；当前测试套件为 57 项，全部通过。

### 6. 多级图设计

- 确立 L0 全量审计图、L1 规范化过程图、L2 状态传播图、L3 运行时检测图四级投影。
- 明确底层“全量”指观测边界内的事件和证据完整，不等于为每个工具创建专用节点。
- 明确每级聚合保留 child ID/digest、证据完整度和 omitted 信息，支持从报警回查底层。
- 已实现 `build_multi_level_graph`，并接入真实 Agent 验证脚本；每次真实执行同时产出
  四级图和各级字节/压缩比、L2 对象/激活数、L3 报警数。
- 详见 [多级图设计](MULTI_LEVEL_GRAPH.md)。

### 8. 攻击样例记录协议

- 已冻结“case JSON 是事实源、L0–L3 图是派生视图”的边界。
- 明确只记录外部可见行为，不采集隐藏 thought；Planner / Attacker / Judge 的结构化输出作为可审计辅助证据保存。
- 详见 [AgentDojo 样例记录与检测协议](AGENTDOJO_CASE_PROTOCOL.md)。

### 7. 工程验证

当前测试套件共 57 项，全部通过。实验计划、结果摘要和实现分别见：

- [图设计说明](GRAPH_DESIGN.md)
- [图状态摘要公开实验结果](GRAPH_SUMMARY_RESULTS.md)
- [图状态摘要实验计划](../experiments/GRAPH_SUMMARY_PLAN.md)

2026-09-08 又使用真实 DeepSeek AgentLAB 执行完成四级图验证：4 个会话、5 个工具
Action、5 个持久 State、3 条跨轮激活链；工具 Action/返回捕获率和会话捕获率均为
100%。L1/L2/L3 相对 L0 大小为 62.9%/18.1%/31.9%，L3 检测报警数为 0。完整产物见
`experiments/real_agent_multilevel_live/real_normal_validation.json`。

## 尚未完成

- 尚未系统覆盖攻击数据集中的所有入口、Effect 类型和跨轮攻击路径；29 条 v0
  标注中仍有 `partial` 结果，需要补原始轨迹；
- 尚未在完整 29 条样例上完成严格 oracle 对齐的检测器评估；
- 尚未完成 150 轮真实 OpenClaw 任务的在线复现实验；
- 尚未验证摘要压缩对攻击检测率和误报率的影响；
- 尚未接入 hidden-state probe、注意力探针等可选监控器。

## 当前最重要的判断

现有结果足以把过程图 v0 作为攻击检测实验的基础，但不能宣称图已经覆盖所有攻击语义。下一阶段应通过攻击样例暴露图的边界，而不是继续抽象地增加节点类型。

## 下一步

1. 冻结图 v0，整理一批带成功 / 失败对照的真实攻击样例。
2. 为每个样例标注攻击入口、关键 Action、持久 Effect、State 传播和成功条件。
3. 在 AgentLAB recorder 中补 session/phase、字段级值流和外部副作用快照证据。
4. 在完整图、固定窗口、`effect_ledger` 和含 process ledger 的摘要上执行检测比较。
5. 以“检测性能损失—压缩比例—误报率—证据完整度”联合评估图摘要。

## 安全与数据边界

真实任务原始轨迹可能包含文件内容、用户输入或外部返回，不直接提交到公共仓库。仓库只保留代码、测试、设计文档和脱敏后的指标；在线 LLM 实验使用运行时密钥，不写入文件。
