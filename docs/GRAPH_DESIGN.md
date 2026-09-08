# GreatWallGuard 图设计说明

## 1. 设计目标

GreatWallGuard 的图不是攻击分类器，也不是黑名单或白名单。它的唯一职责是：

> 用稳定、可回查、可压缩的结构，记录 Agent 在多轮执行中看到了什么、做了什么，以及留下了哪些持久影响。

攻击检测、权限判断和异常分析都在图之上运行。这样可以避免把某一种攻击假设硬编码进基础表征。

## 2. 统一流转

```text
输入 / 返回
    ↓
Observation（进入观测边界的内容）
    ↓
Action（Agent 发起的工具或后台操作）
    ↓
Effect（该操作报告或推断的影响）
    ↓
State（对象留下的可持续版本）
    ↓
下一轮读取、规划或继续操作
```

复杂的长程任务只是上述流转的重复和连接：

```text
输入 → 自主执行 → 输出 → 自主执行 → 输出 → 状态被再次读取
```

图不保存完整上下文作为运行时状态，而是保留影响后续执行的结构和证据引用。

## 3. 节点定义

| 节点 | 表达的问题 | 典型字段 |
|---|---|---|
| `Observation` | 哪个输入、返回或上下文进入了观测边界？ | `source`、`integrity`、`content_ref`、`turn` |
| `Action` | 哪个工具或后台操作被发起？ | `tool`、`call_id`、`arguments_digest`、`decision`、`execution_status` |
| `Effect` | 该操作预期或报告了什么影响？ | `kind`、`target`、`operation`、`persistent`、`reversible` |
| `State` | 某个对象留下了哪个版本？ | `object_id`、`version`、`fingerprint`、`effect_id`、`commit_evidence` |

当前有限 Effect 词表为：

```text
read | write | create | delete | send | execute | permission_change | unknown
```

`unknown` 是保守的可观测结果，不代表恶意。

## 4. 边定义

| 边 | 含义 |
|---|---|
| `derived_from` | 某个输出或动作关联了哪个观测来源 |
| `causes` | Action 与 Effect 的关系 |
| `updates` | Effect 与 State 版本更新的关系 |
| `reads` | 当前观测读取了哪个历史对象或版本 |
| `next` | 事件在同一执行流中的顺序 |

每条边同时记录证据：

```text
basis  = observed | reported | declared | inferred | unspecified
method = hook / tool_contract / snapshot / adapter / rule / ...
```

证据等级描述“关系是如何得到的”，不把推断关系伪装成事实因果。

## 5. 内容与过程

图中的节点和边负责过程关系；内容索引负责内容本身。两者不是两套互斥节点。

```text
过程层 G：谁在何时对什么对象做了什么
内容层 C：输入、返回和文件中有哪些事实、约束、条件和修订
证据层 R：原文、参数或快照的可回查引用
```

运行时优先保留摘要、哈希、版本和引用；原文只在离线核查或需要回查时读取。
当前 `content_sketch` 支持两种方式：确定性原文片段抽取，以及带引用校验的可选 LLM 抽取。无据命题不能进入摘要。

## 6. 有界运行时摘要

完整图用于审计，运行时使用三个有界组件：

```text
recent_trace
    最近的过程事件、call_id、参数摘要和返回证据

effect_ledger
    每个活跃对象的最新 State 版本、指纹、Effect 类型和证据引用

content_sketch
    任务事实、约束、条件、修订和撤回的带证据摘要
```

当前摘要能稳定保留持久状态，但历史 `call_id` 和返回证据会随窗口缩小而衰减。因此下一步拟增加与 `effect_ledger` 并列的 `effect_process_ledger`：

```text
持久 Effect → 产生它的 call_id → 参数摘要 → 返回证据 → State 版本
```

这不是新的图节点类型，而是同一张图的另一种有界投影。

## 7. 当前边界

- 图目前记录可观测行为，不表示黑盒模型内部推理。
- 工具语义依赖 ToolContractRegistry；未知工具进入 `unknown`，不能自动获得权限。
- 复杂 Bash 内部因果、并发影响和真实外部系统状态仍需适配器或快照验证。
- 图本身不判定良性 / 恶意；检测器需要在图上单独训练和评估。

实现入口：[state_summary.py](../src/greatwallguard/state_summary.py)。
