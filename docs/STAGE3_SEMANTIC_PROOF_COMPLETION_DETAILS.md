# 阶段三：语义证明补全

阶段二能够程序化检查工具角色、参数来源、有限变换、对象范围和预算，但并非所有授权关系都能写成 `select / project / join / aggregate` 等有限算子。例如，“这个邮箱是否属于用户所说的项目负责人”“生成正文是否符合用户要求”“某个计划外工具是否是完成终端效果的合理中间步骤”，都需要理解任务语义。

阶段三要解决的不是重新判断整项任务是否安全，而是：**当阶段二已经定位到一条无法程序化计算的授权关系时，如何只补全这条局部语义关系，同时阻止 LLM 扩大用户授权或把证据不足误判为越权。**

为此，我们提出 **Semantic Proof Completion**。系统将阶段二的证明断点转换为一个原子 Proof Obligation，从授权 DAG 和运行时证据中切出最小证明包，再让 LLM 对这条局部关系给出带证据的三态结论。程序负责限定问题、选择证据和校验冲突；LLM 只负责解释无法由有限算子计算的语义。

```text
Stage 2 REVIEW
       ↓
原子 Proof Obligation
       ↓
Authorization DAG + Runtime Evidence 的局部切片
       ↓
SUPPORTED / CONTRADICTED / NEED_EVIDENCE
       ↓
程序校验、一次有界补证和终局处置
       ↓
ALLOW / DENY / CONFIRM
```

## 1. 从未闭合证明到局部语义问题

进入 `REVIEW` 并不意味着整条执行轨迹都无法理解。多数情况下，阶段二已经证明了工具、参数值、来源路径和范围，只剩一条关系无法闭合。例如：

```text
Authorization DAG：
recipients ← “项目负责人”的邮箱

Runtime Evidence：
alice@example.com 来自项目成员列表，
对应角色为 project owner

Agent 候选调用：
send_email(recipients=["alice@example.com"])
```

阶段二能够证明 Alice 的邮箱来自允许的项目资料，也能证明 `send_email` 是用户授权的终端效果，但无法仅靠字符串和关系算子判断 `project owner` 是否满足用户所说的“项目负责人”。真正缺失的只是：

```text
role(project owner)
        是否满足
authorized_role(项目负责人)
```

同样，工具动态性也可能留下局部断点。部署契约可能表明 `input_to_webpage` 可以是 `checkout` 的中间能力，但阶段二无法根据字段相等关系判断本次网页输入是否只是完成结算所需，还是新增了独立行为。此时未决关系是：

```text
instrumental_effect_link(
    input_to_webpage,
    checkout
)
```

**Key Insight.** LLM 不需要重看完整长程轨迹，只需证明阶段二缺失的一个类型化关系。授权边界继续由阶段一的 DAG 决定，执行事实继续由阶段二记录；阶段三只允许在二者之间补充一条有明确对象和作用域的语义证明。

## 2. Proof Obligation 与最小证据包

阶段二的 `REVIEW` 首先由程序分类：

```text
semantic_unresolved
事实已经存在，但语义关系无法用有限算子判断
→ 进入语义证明补全

evidence_missing
缺少返回、字段、版本或能力连接
→ 继续程序化取证，不允许 LLM 猜测

policy_confirmation
缺少的是用户授权，而非环境事实
→ 请求用户确认
```

只有 `semantic_unresolved` 进入 LLM 审计。程序根据阶段二失败的位置生成 Proof Obligation，常见类型包括：

```text
parameter_binding
候选参数是否符合用户的语义描述？

condition_satisfaction
运行时对象是否满足用户指定条件？

delegation_scope
用户是否允许当前来源决定这个字段或效果？

instrumental_effect_link
动态中间工具是否服务于已授权终端 Effect？

observation_scope
当前读取是否仍属于用户允许的数据范围？
```

一个 Proof Obligation 包含：

```text
需要证明的关系类型
可信用户授权片段
当前候选工具调用
授权 DAG 中对应的 Effect / Binding / Delegation
运行时证据中相关的来源、字段和值
本次证明允许影响的 Effect、字段和候选值
```

例如：

```json
{
  "type": "parameter_binding",
  "authorized_claim": "收件人必须是项目负责人",
  "candidate_call": {
    "tool": "send_email",
    "recipients": ["alice@example.com"]
  },
  "evidence": [{
    "ref": "E0",
    "source": "read_project_members",
    "path": "members[2]",
    "value": {
      "role": "project owner",
      "email": "alice@example.com"
    }
  }],
  "scope": {
    "effect": "external_message",
    "field": "recipients",
    "candidate_value": "alice@example.com"
  }
}
```

证据包只包含可信用户请求、候选调用、原子问题及其直接相关证据，不包含整个对话、无关工具返回或 Agent 隐藏推理。这样，LLM 不需要自行寻找“要判断什么”和“哪段证据相关”，外部内容也不能借长上下文重新定义审计目标。

## 3. 三态语义证明与程序校验

LLM 不能输出笼统的 `safe / unsafe`，而必须给出三态结论：

```text
SUPPORTED
现有证据支持当前局部授权关系。

CONTRADICTED
现有证据明确反驳当前局部授权关系。

NEED_EVIDENCE
现有证据既不能证明支持，也不能证明冲突。
```

三态设计区分了两个不同命题：

```text
没有证据证明行为得到授权
≠
已经有证据证明行为违反授权
```

`SUPPORTED` 必须引用具体证据，证明当前 Effect、字段和候选值，不能仅说明调用“与任务相关”。如果 Alice 的成员记录明确写着 `project owner`，审计器可以在当前邮件收件人范围内支持该 Binding；这项证明不能扩展到附件、其他效果或后续无关任务。

`CONTRADICTED` 必须提交有限冲突证书，例如：

```json
{
  "conflict_type": "fixed_value_conflict",
  "actual_value": "eve@example.com",
  "authorized_value_or_constraint": "alice@example.com",
  "operator": "eq",
  "evidence_refs": ["trusted_user_request", "pending_call"]
}
```

程序随后验证证据引用、冲突类型、操作数和比较关系。证据不存在、操作数缺失或声称的冲突并不成立时，结论自动降为 `NEED_EVIDENCE`。因此，LLM 可以提出语义判断，但不能凭一句“看起来异常”产生高置信阻断。

`NEED_EVIDENCE` 必须指出缺失事实和建议查询。如果缺失信息可以通过安全的只读工具取得，系统只允许进行一次有界补证，然后使用同一个 Proof Obligation 重新审计；如果缺失的是用户是否授予权限，则不能通过环境查询或 LLM 推断，必须请求用户确认。

## 4. 贯穿案例

用户请求：

> 给项目负责人发送一封项目完成通知。

阶段一生成：

```text
Effect       = external_message
recipients   ← role(项目负责人).email
subject/body ← 用户目标约束下的生成字段
Budget       = 1
```

阶段二记录真实工具返回：

```json
{
  "members": [
    {
      "name": "Alice",
      "role": "project owner",
      "email": "alice@example.com"
    }
  ]
}
```

Agent 提出：

```text
send_email(recipients=["alice@example.com"], ...)
```

阶段二能够证明邮箱来自成员列表，但有限 DSL 中没有足够规则判断 `project owner` 与“项目负责人”的语义对应，因此生成：

```text
type = parameter_binding
question = Alice 的角色是否满足“项目负责人”？
candidate_value = alice@example.com
evidence = members[0].role + members[0].email
```

如果阶段三返回：

```text
SUPPORTED
E0.role = project owner，E0.email = alice@example.com
```

则当前调用获得一条仅限 `external_message.recipients=alice@example.com` 的语义证明，统一管线将其收敛为 `ALLOW`。

如果证据明确写着 Alice 是 `external visitor`，审计器可以提交 `role_mismatch` 冲突；程序校验后收敛为 `DENY`。如果成员记录没有角色字段，则结果必须为 `NEED_EVIDENCE`：系统可以读取角色信息；若无法取得，则不能让 LLM 猜测，最终根据风险和缺失授权路由到 `CONFIRM` 或 `DENY`。

对于动态工具，同一过程适用于 `instrumental_effect_link`。LLM 只判断当前中间调用是否是范围保持的实现步骤；它不能由此新增终端 Effect，也不能把一次性的判断变成全局工具白名单。

## 5. 当前实现和边界

当前实现已经包含 Proof Obligation 生成、最小证据包、三态语义审计、有限冲突证书校验、一次证据恢复接口和终局处置。统一在线管线的处理顺序为：

```text
Stage 2 ALLOW → ALLOW
Stage 2 ALERT → DENY
Stage 2 REVIEW
    → 构造 ProofPacket
    → 语义审计
    → SUPPORTED → ALLOW
    → 有效 CONTRADICTED → DENY
    → NEED_EVIDENCE → 一次补证并重试
    → 仍未决 → ALLOW / DENY / CONFIRM 终局策略
```

当前代码把 `SUPPORTED` 保存为本次调用的 `SemanticProof` 并直接形成统一决策，尚未把所有语义证明持久写回 Authorization DAG。方法上更完整的形式是生成带 Effect、字段、候选值、对象版本和任务阶段作用域的运行时证明边；只有用户确认或可复用委托才适合形成受限 DAG Delta，普通一次性语义结论不能升级为永久白名单。

阶段三的实验来自阶段二留下的真实 `REVIEW` 调用，而不是重新抽取一批容易分类的攻击样本。当前结果表明，局部证明包可以释放一部分正常动态行为，并保持有效攻击直接自动放行为零；但终局强制裁决仍会保守拒绝部分正常轨迹。因此，阶段三的主要改进方向不是继续强化二分类 Prompt，而是根据 `missing_fact + suggested_query` 完成真实只读补证，并将可复用证明以有界作用域写回运行时授权状态。

阶段三最终完成的不是一次新的攻击分类，而是对前两阶段证明链的有限补全：

```text
Authorization DAG 中的未决授权关系
                +
Runtime Evidence 中的相关事实
                ↓
类型化 Proof Obligation
                ↓
受约束的语义证明
                ↓
ALLOW / DENY / CONFIRM
```

其核心原则是：**程序决定需要证明什么、选择哪些证据并校验结论；LLM 只解释一个局部语义关系。它不能新增终端效果、扩大数据范围或代替用户授予权限。**
