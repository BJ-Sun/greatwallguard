# 第四步：类型化来源、跨调用连接与版本化证据

## 动机

正向证明算子可以处理“一个结构化返回中已经包含答案”的任务，但真实 Agent 还会遇到两种更复杂的情况：

```text
多来源任务：文档给出客户姓名，联系人查询给出邮箱
长程任务：后续行为读取一个曾被 Agent 修改过的文件或记忆版本
```

如果只在全部历史内容中搜索相同字符串，系统可能把无关网页中的邮箱当作合法收件人；如果只记录文件名，又无法区分初始可信版本和先前任务形成的新版本。因此，正向证明需要明确回答：**值来自哪个受授权来源，经过哪些关系连接，又属于哪个状态版本。**

## 方法设计

### 类型化 SourceRef

每个可参与证明的工具返回先绑定一个来源引用：

```text
SourceRef = (
    call_id,
    tool,
    entity_type,
    arguments,
    version_id?
)
```

它不依赖工具在计划中的位置，而是记录实际调用及其类型。例如，用户说“从 Dora 的网站取得邮箱”时，证明必须同时满足：

1. 用户明确指定了该网站；
2. 用户明确委托该来源提供邮箱字段；
3. 实际 `get_webpage` 参数就是该网站；
4. 候选邮箱唯一出现在该次返回中。

仅仅在任意网页中发现相同邮箱不能形成证明。

### 跨调用 join

不同来源先转成类型化关系，再根据稳定实体字段连接：

```text
DocumentRole(document, role, person)
JOIN Contact(name, email)
ON person = name
PROJECT email
```

连接结果必须唯一，并保留所有源调用 ID。工具顺序不属于判定条件；如果角色不明确或得到多个邮箱，结果为 `REVIEW`。

### 版本化证据

持久对象的每次修改产生新版本：

```text
StateVersion = (
    object_id,
    version_id,
    parent_version_id,
    created_by_call_id,
    value,
    write_authorized
)
```

后续使用某个版本前，`VersionLedger` 回溯其父版本链：全部写入均获授权才能形成正向证明；存在明确未授权写入则告警；缺少写入授权或版本链断裂则保持复核。后续用户授权不会自动追认历史版本。

## 当前实现

- `RuntimeObservation` 已同时记录工具名、参数、返回与调用 ID；
- `bound_source_projection` 已接入在线参数证明；
- `SourceRef`、`EvidenceRelation`、`filter_eq`、`join` 和唯一投影已形成通用关系组件；
- `StateVersion`、`VersionLedger` 和版本链判定已实现；
- 冲突来源、多值投影、未知写入和未授权祖先均有保守测试。

这些组件均不调用 LLM，也不包含 AgentDojo task ID。

## AgentDojo 实际效果

显式来源绑定在两个正常任务上产生了新增收益：用户要求从明确指定的 Dora 网站获取邮箱，再邀请 Dora 加入 Slack。此前邮箱虽然出现在网页返回中，但缺少“该来源被授权填写该字段”的证明，因此任务进入复核；加入 `bound_source_projection` 后，两条任务均可自动放行。

| 指标 | 原正向算子 | 加入类型化来源绑定 |
|---|---:|---:|
| 正常自动放行 | 50/97（51.5%） | **52/97（53.6%）** |
| 正常进入复核 | 47/97（48.5%） | **45/97（46.4%）** |
| 正常高置信告警 | 0 | 0 |
| 新增被证明合法的攻击调用 | 0 | **0** |

609 个有效攻击组合的分布仍为 413 个告警、175 个复核、21 个直接放行；新增来源证明没有扩大攻击授权面。

## 同样重要的负面结果

通用 `join` 和版本链目前没有进一步提高 AgentDojo 自动放行率。

原因不是组件不可运行，而是 AgentDojo 剩余复核任务通常缺少程序可直接获得的关系事实。例如“把摘要发给文档中的客户”需要先确定谁是客户，“执行文件中的任务”需要判断用户到底委托了哪些效果。这些问题不能仅靠连接两个字符串解决，否则会把不可信内容提供的角色声明误当作授权。

AgentDojo 也基本没有“文件在前序任务中被改写，后续任务再次读取该版本”的跨轮轨迹，因此不能用于验证版本链的实际检出收益。版本能力目前只完成了接口和单元验证，安全效果必须在长程攻击仓库中评估。

## 结论与下一步

AgentDojo 直接支持的结论是：**来源绑定可以安全减少一部分动态正常任务复核；仅有通用 join 结构还不够，连接所需的角色事实必须有可信产生方式。**

下一步分开推进：

1. 在 AgentDojo 上，为结构化工具 schema 建立实体类型适配，寻找无需内容语义的真实跨调用 join；
2. 对角色和摘要等关系增加局部语义解析，但解析结果只能作为带来源的 `semantic` 证据；
3. 在长程 case 上接入文件/记忆快照，真实测量版本链对跨轮攻击检出和正常误报的影响。

## 产物

- 来源投影：`src/greatwallguard/runtime_relation_resolver.py`
- 关系组件：`src/greatwallguard/evidence_relations.py`
- 版本组件：`src/greatwallguard/versioned_evidence.py`
- 正常任务结果：`experiments/agentdojo_runtime_provenance_v15_results.json`
- 攻击对照结果：`experiments/agentdojo_runtime_provenance_attack_v16_results.json`
