# 阶段二：Deterministic Runtime Proof

阶段一将可信用户请求编译为 Authorization DAG，固定了允许的终端 Effect、关键参数的形成关系、数据来源、适用条件和消费预算，同时将具体工具返回与合理中间路径留到运行时确定。本阶段的目标是判断 Agent 动态产生的候选调用能否由这张授权图和真实执行证据推出。为此，我们将 **Deterministic Runtime Proof** 部署在 Agent 与工具之间的调用网关，并将证明过程分为两部分：首先记录真实工具返回并执行 DAG，求出当前证据下允许的工具能力和参数；随后将该结果与 Agent 候选调用比较，并验证条件、状态版本和消费预算，最终输出 `ALLOW / ALERT / REVIEW`。

```text
真实工具返回
      ↓
证据提取与授权求值
      ↓
当前可证明的工具能力、参数及来源
      ↓
调用检查与状态验证
      ↓
ALLOW / ALERT / REVIEW
```

## 1. 证据提取与授权求值

Authorization DAG 中的 `ToolResult(read_todo)` 只规定允许使用哪类数据，具体值要等真实工具执行后才能确定。工具返回通常还是嵌套的列表或对象，DAG 无法直接知道哪次调用、哪个字段和哪个对象版本可以用于参数计算。为解决这一问题，我们设计运行时证据记录与 DAG 求值机制：网关保存完整工具返回，将其展开为字段级事实，再用这些事实执行 DAG 中的 Binding 和能力关系。

当前实现维护两类基本证据：

```text
RuntimeObservation
├── call_id      工具调用的唯一标识
├── tool         实际工具名称
├── arguments    本次调用参数
└── value        工具真实返回

RuntimeFact
├── call_id      所属调用
├── tool         来源工具
├── path         返回值中的字段路径
└── value        路径对应的叶子值
```

例如，`read_todo` 返回两条任务记录后，网关保存完整 Observation，并生成字段级 Fact：

```text
read-1 : read_todo : [0].status       = unfinished
read-1 : read_todo : [0].owner_email  = alice@example.com
read-1 : read_todo : [1].status       = finished
read-1 : read_todo : [1].owner_email  = bob@example.com
```

一次读取按照下面的顺序进入授权求值：

```text
Agent 发起读取调用
        ↓
网关根据部署方读取策略检查调用对象和范围
        ↓
工具执行并返回
        ↓
网关记录 RuntimeObservation 与 RuntimeFact
        ↓
DAG 使用匹配字段执行 Binding 查询
```

Fact 只表示某个值出现于特定调用和字段路径。DAG 随后沿 `data_dep` 执行 `select / project / join / aggregate / compute / normalize / template`，并通过 `binds(field)` 得到安全关键参数的当前授权值。例如：

```text
read_todo 的真实返回
→ select(status = unfinished)
→ project(owner_email)
→ recipients = {alice@example.com}
```

参数求值同时保留所使用的 `call_id`、字段路径和 DSL 算子，使结果可以追溯到具体运行时证据。部署方声明的 Source Alias 可以容纳语义等价的读取工具，同时保持可接受来源集合有限。

动态中间工具也采用相同的求值原则。部署方通过 Capability Rule 声明某类中间工具可以服务于哪个已授权终端工具，以及二者必须保持一致的关键字段；只有这些字段能够由终端 Effect 的 Binding 证明时，系统才生成临时工具能力。规则存在但字段关系尚未闭合时，该能力保持未决。由此，授权求值的结果同时包含动态参数和当前证据能够支持的读取、中间工具能力。

对于文件、记忆等持久对象，网关可以同时记录：

```text
object_id / version_id / parent_version_id
created_by_call_id / write_authorized
```

运行时证据因此同时回答三个问题：值是什么、来自哪里、依赖哪个对象版本。版本是否可用会在第二部分与候选调用一起验证。

## 2. 调用检查与状态验证

第一部分求出的参数和能力描述“当前证据能够证明什么”，但还没有回答 Agent 当前提出的调用是否符合这些结果，以及相关授权在此刻是否仍然有效。为解决这两个问题，我们将第二部分分为连续的两项检查：先核对候选调用本身，再验证支撑该调用的授权状态。

```text
当前授权求值结果 + Agent 候选调用
              ↓
调用一致性检查
├── 工具与 Effect
├── 参数完整性
├── 固定参数
└── 动态参数与来源
              ↓
授权状态验证
├── Constraint
├── 对象版本
└── Budget
              ↓
ALLOW / ALERT / REVIEW
```

**调用一致性检查。** 证明器先判断工具角色：终端工具需要对应 DAG 中已有的 Effect；读取工具需要命中 DAG Source、部署方声明的等价来源或读取策略；计划外中间工具需要具有第一部分求得的临时能力；产生新终端 Effect 的工具需要用户明确给出 Effect 级委托。部署方读取策略只处理少量实现差异：纯被动读取可以直接记录，带对象范围的读取需要命中授权来源，可能通过请求参数向外传输数据的读取还要验证目标地址和携带参数。

工具角色成立后，证明器根据 Effect Contract 取得安全关键字段和必填字段，再按参数类型逐项核对：

```text
必填字段缺失
→ ALERT: required_parameter_missing

IR 显式禁止该字段，但实际调用提供了值
→ ALERT: parameter_not_authorized

字段来自用户字面值
→ 比较实际值与授权值

字段来自运行时 Binding
→ 比较实际值与第一部分的 DAG 求值结果
```

固定参数直接与用户字面值比较。动态参数则比较 DAG 求值结果与 Agent 实际参数：

```text
DAG 对已观察返回的计算结果
                ↕
Agent 实际提交的参数
```

两者一致时，Binding 得到证明，并携带来源调用、字段路径和计算算子。路径和 URL 等范围型参数使用结构化包含关系：授权目录可以覆盖子路径，授权 URL 可以覆盖相同域名下的指定子路径；兄弟目录、不同域名和更宽的路径范围不属于原授权。当前实现对“实际值不在已求得结果中”和“查询因缺少输入而无法完成”均保守输出 `REVIEW: authorized_effect_has_unproved_binding`，因为有限求值器尚未在所有算子上区分穷尽后的不匹配与不完整求值。

**授权状态验证。** 候选调用与授权求值结果一致后，证明器再检查这份授权在当前状态下是否有效。首先执行 DAG 中的 Constraint：谓词被真实证据否定时输出 `ALERT`，缺少输入时输出 `REVIEW`。随后检查参数依赖的持久对象版本：明确由未授权写入产生的版本输出 `ALERT`，形成过程未知的版本输出 `REVIEW`。最后检查 Budget，既包括 Effect 总次数，也包括按关键 Binding 的计数。例如：

```text
每个 recipients 最多一次
总邮件数最多十次
```

候选调用通过验证后先进入 `pending` 状态，工具成功产生 Effect 后才增加计数。失败调用不消费授权，撤销的 Effect 和已经耗尽的 Budget 会在后续调用中形成明确冲突。

调用一致性和授权状态共同决定最终结果：

```text
ALLOW
工具、参数、来源、条件、版本和 Budget 均已得到程序证明。

ALERT
至少一项必要关系与授权存在确定冲突。

REVIEW
尚未发现确定冲突，但至少一项必要关系缺少证明。
```

`REVIEW` 携带具体问题类型：

```text
semantic_unresolved
有限算子无法判断开放语义关系
→ 阶段三构造局部语义证明

evidence_missing
缺少工具返回、字段、对象版本或参数连接
→ 补充真实证据；无法补证时阻止执行或请求用户处理

policy_confirmation
用户给外部来源的委托范围不明确
→ 请求用户确认授权边界
```

每次判定还返回候选 Effect、问题字段、Source 调用、DSL 算子、字段级证据路径和具体原因。这些信息用于解释决策，并为阶段三提供最小证据入口。

## 3. 贯穿案例

用户要求：

> 读取指定 TODO 文件，给其中每个未完成任务的负责人发送一次提醒，最多发送十封。

阶段一已经生成：

```text
Effect       = external_message via send_email
recipients   ← read_todo → select(unfinished) → project(owner_email)
subject      = "Task Reminder"
body         ← read_todo → select(unfinished) → project(task) → template
attachments  = absent
Constraint   = status == unfinished
Budget       = 每位负责人一次，总计十次
```

第一部分首先提取证据并求值授权：

```text
Agent → read_todo(用户指定路径)
Gateway → 检查读取来源和路径范围
Tool → 返回 TODO 记录
Gateway → 保存 Observation 与字段级 Fact
DAG → 导出 recipients=Alice 及对应 body
```

第二部分在 Agent 提出 `send_email` 时检查实际调用：

```text
1. send_email 对应已授权 external_message
2. recipients / subject / body / attachments 均已表达
3. subject 与用户字面值一致，attachments 为空
4. 实际 recipients 和 body 与 DAG 求值结果一致
5. Alice 对应记录满足 status=unfinished
6. Alice 尚未发送，总数未超过十次
7. 结果：ALLOW
```

不同执行情况得到不同结果：

```text
实际收件人为 Bob，DAG 只导出 Alice
→ REVIEW: authorized_effect_has_unproved_binding

TODO 返回缺少 status，select 无法求值
→ REVIEW: evidence_missing

实际调用添加了未授权附件
→ ALERT: parameter_not_authorized

再次给 Alice 发送且每人预算为一次
→ ALERT: authorization_binding_budget_exhausted
```

阶段二能够程序化验证 Effect、工具能力、关键参数、有限数据来源、确定性计算、结构化条件、对象范围、消费预算，以及已接入版本账本的持久状态来源。开放语义关系由阶段三补全；缺失事实需要真实工具或环境补证；宽泛委托需要可信用户确认。版本账本只有在相应 Agent 环境提供完整持久读写事件后，才能端到端验证文件、记忆或工作区版本的形成过程。
