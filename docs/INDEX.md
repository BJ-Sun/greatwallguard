# GreatWallGuard 研究推进索引

这是新会话的最小上下文入口。建议按以下顺序阅读和推进。

当前研究主线：[任务内持久状态的效果授权](AUTHORIZATION_AND_EXECUTION_GRAPH_V1.md) —— 从长程攻击的分步隐蔽性与正常执行的多变性出发，梳理相关工作的能力边界、状态版本授权思路及配对验证。第一版代码和试验数字另见[原型实现记录](PROTOTYPE_NOTES.md)。

研究问题与此前路线：[方法设计与验证状态](METHOD_DESIGN_AND_VALIDATION.md) —— 方法主线、早期实验结论及决定性验证。

最新窄实验：[真实会话中的收件人来源绑定](RECIPIENT_SOURCE_BINDING_PILOT.md) —— 恢复原生读取路径，对照条件正常发送与攻击额外发送，并说明尚不能泛化的边界。

## A. 先了解当前系统

1. [研究动机与方法主线](MOTIVATION.md) —— 从组合攻击与正常路径变化，说明为何要对照用户授权和跨轮效果，并明确现有证据的边界。
2. [图设计与当前进展总览](GRAPH_DESIGN_AND_CURRENT_PROGRESS.md) —— 面向读者的统一说明、实验结果和下一步。
3. [图设计说明](GRAPH_DESIGN.md) —— 节点、边、证据、内容层和有界摘要。
4. [图表征规范](REPRESENTATION_SPEC.md) —— 当前过程图和内容索引的正式边界。
5. [当前进展](PROGRESS.md) —— 已完成、未完成和下一步判断。
6. [简易 TaskScope 原型](TASK_SCOPE_MINIMAL.md) —— 仅基于正常任务、Agent 能力和工具 schema 的第一版生成器。
7. [无注入正常任务对照集](BENIGN_CONTROL_DATASET.md) —— 六类攻击目标的真实正常重跑、质量门槛、覆盖率与评估边界。
8. [TaskScope × Effect 图配对实验](EFFECT_SCOPE_PILOT.md) —— 25 对匹配评测、305 条攻击广度审计和双 Effect 良性压力测试。
9. [逐项 Effect 承诺请求侧试验](EFFECT_COMMITMENT_PILOT.md) —— 标签隐藏的逐轮请求标注、承诺匹配、含糊续办和工作区 Effect 缺口。

## B. 读取实验结论

5. [图状态摘要公开实验结果](GRAPH_SUMMARY_RESULTS.md) —— 真实长时任务的聚合压缩与覆盖率结果。
6. [图状态摘要实验计划](../experiments/GRAPH_SUMMARY_PLAN.md) —— 实验设置、指标和预算。
7. [过程与内容双维度验证](../experiments/TWO_AXIS_VALIDATION.md) —— 早期正常任务验证。
8. [攻击样例标注表](ATTACK_ANNOTATIONS.md) —— 29 条已有样例的入口—Action—Effect—State—成功条件标注。
9. [图覆盖审计](GRAPH_GAP_AUDIT.md) —— 当前图的最小缺口集合。
10. [图检测基线](GRAPH_DETECTION_BASELINE.md) —— 第一版结构信号与评估协议。
11. [多级图设计与实验验证报告](MULTI_LEVEL_GRAPH_REPORT.md) —— 全量审计图到运行时压缩图的统一分层、实现和真实 Agent 验证结果。
    另见 [多级图设计细则](MULTI_LEVEL_GRAPH.md)。
12. [AgentDojo 样例记录与检测协议](AGENTDOJO_CASE_PROTOCOL.md) —— 原始 case、图派生视图和检测评估的统一记录规范。
13. [真实 OpenClaw 攻击数据生产计划](https://github.com/BJ-Sun/openclaw-agentlab/blob/real-openclaw-agentdojo/docs/REAL_ATTACK_DATASET_PLAN.md) —— seed 规模、变体、批次、产物和时间计划。

## C. 下一阶段研究问题

### C1. 攻击数据集

- 覆盖用户直接输入、间接返回、记忆、持久化文件等入口；
- 同时包含单步、分步组合、成功、失败和良性对照；
- 为每个样例标注 `入口 → Action 序列 → 持久 Effect → State 传播 → 成功条件`；
- 先使用已有 AgentDojo / 长城攻击案例，再补齐行为覆盖表中的缺口。

### C2. 图覆盖审计

对每个攻击样例检查：

```text
入口是否被记录？
弱步骤是否与后续持久 Effect 关联？
跨轮 State 是否被正确读取和更新？
失败攻击在哪里中断？
关键证据能否从摘要回查？
```

如果无法表达，先区分是采集失败、内容压缩失败，还是图结构确实不足，避免为单个攻击子类打补丁。

### C3. 最小图检测基线

先不引入复杂模型，比较以下信号：

1. 当前 Action 是否偏离任务目标；
2. Effect 是否超出任务所需最小权限；
3. 多轮 State 传播是否形成未授权链路；
4. 外部来源是否通过中间状态影响后续高影响操作。

比较完整图、固定窗口、`effect_ledger` 和完整有界摘要，分别报告检测率、误报率、最早检测轮次和压缩比例。

### C4. 下一步实现优先级

```text
攻击样例整理（29 条 v0 标注）
    ↓
图覆盖审计（M1–M5）
    ↓
effect_process_ledger（已实现）
    ↓
规则 / 轻量模型检测基线（已实现第一版）
    ↓
压缩后检测性能评估
    ↓
再决定是否引入白盒模型、注意力探针或隐藏状态探针
```

## D. 新会话建议的第一条任务

> 读取本索引、`GRAPH_DESIGN.md` 和 `PROGRESS.md`，选取 20–30 个已有攻击样例，建立攻击入口—Action—Effect—State 标注表，并报告当前图无法表达的最小缺口集合。
