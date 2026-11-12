# 阶段二：Deterministic Runtime Proof

阶段一将可信用户请求编译为 Authorization DAG，已经固定了允许的终端 Effect、关键参数的形成关系、数据来源、适用条件和消费预算，同时将具体工具返回与合理中间路径保留到运行时确定。本阶段的目标是在 Agent 动态执行期间，判断每个候选工具调用能否由这张授权图和已经取得的真实证据推出。这里需要解决三个问题：工具返回以多种嵌套结构逐步到达，如何将其绑定到 DAG 中尚未实例化的 Source；读取、搜索和中间工具可以动态变化，如何容忍合理路径而不扩大终端授权；实际参数可能经过筛选、关联和计算形成，如何独立复算并区分授权闭合、明确冲突与证据不足。为此，**Deterministic Runtime Proof** 部署在 Agent 与工具之间的调用网关，依次完成运行时证据记录、DAG Source 绑定、工具角色识别、参数与 Binding 求值、条件和预算检查，最终输出 `ALLOW / ALERT / REVIEW`。

阶段二接收以下输入并产生三态证明结果：

```text
输入
├── Authorization DAG
├── 候选工具调用：call_id / tool / arguments
├── 已完成调用及其真实返回
├── Observation Contract 与 Capability Rule
├── 持久对象的版本证据（如果存在）
└── Effect 的消费账本

输出
├── ALLOW   授权所需关系均已得到程序证明
├── ALERT   实际行为与授权存在确定冲突
└── REVIEW  未发现确定冲突，但证明尚未闭合
```

阶段二的关键观察是：Agent 可以采用不同的规划路径，但真实副作用最终都会落实为可观察的工具和参数；参数又必须来自用户字面值或先前工具返回。系统因此可以在 Agent 之外，对同一批运行时数据执行 Authorization DAG 规定的查询，再将独立计算结果与 Agent 的实际调用比较。

## 1. 将真实执行绑定到 Authorization DAG

Authorization DAG 中的 `ToolResult(read_todo)` 只规定允许使用哪类数据，尚未指向某次真实调用。运行时网关需要记录“哪个工具在何时返回了什么”，并将嵌套结果展开为可定位的字段事实。当前实现维护两类证据：

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

读取调用按照下面的顺序进入证明状态：

```text
Agent 发起读取调用
        ↓
网关根据 Observation Contract 检查读取角色和范围
        ↓
工具执行并返回
        ↓
网关保存 RuntimeObservation 与 RuntimeFact
        ↓
DAG 中匹配的 Source 节点获得可求值证据
```

Fact 只证明某个值出现于特定工具返回和字段路径。该值是否可以填入某个参数，还需要沿 DAG 中的 `data_dep` 与 `binds` 关系完成后续证明。

对于文件、记忆等持久对象，网关还可以同时记录 `object_id / version_id / parent_version_id / created_by_call_id / write_authorized`。当某个参数依赖该对象时，阶段二会检查当前读取版本的形成过程是否具有授权；版本未知形成 `REVIEW`，明确由未授权写入产生则形成 `ALERT`。

## 2. 对候选调用执行渐进式程序证明

当 Agent 提出一个候选调用时，网关在工具执行前依次证明工具角色、关键参数、动态 Binding、条件与预算。前一项存在明确冲突时立即输出 `ALERT`；缺少必要证据时停止并生成带类型的 `REVIEW`。

```text
候选工具调用
      ↓
1. Effect 与工具角色
      ↓
2. 关键参数完整性及固定参数
      ↓
3. 动态 Binding、来源与版本
      ↓
4. Constraint、对象范围与 Budget
      ↓
ALLOW / ALERT / REVIEW
```

证明器首先检查 **Effect 与工具角色**，确定当前工具在授权关系中的位置：

```text
终端工具
→ 是否对应 DAG 中已有的 Effect 节点

读取工具
→ 是否为 DAG Source 指定的工具或部署方声明的等价来源

计划外中间工具
→ 是否命中 Capability Rule，且参数能够连接到已授权终端工具

新的终端 Effect
→ 是否存在用户明确给出的 Effect 级委托
```

动态读取通过 Source 与 Observation Contract 约束。`passive` 读取可以直接记录，`scoped` 读取需要命中 DAG 中的授权来源，具有外发能力的 `outbound` 读取还要检查其请求参数是否由可信用户直接授权。

动态中间工具通过阶段一介绍的 Capability Rule 派生临时能力。例如：

```text
CapabilityRule
  prerequisite_tool = add_to_cart
  terminal_tool     = checkout
  links             = product_id → product_id
```

只有 `add_to_cart.product_id` 能够由 `checkout` 的已授权商品 Binding 证明时，中间调用才可自动放行；规则存在但参数连接尚未证明时进入 `REVIEW`。这样可以容纳正常的动态工具路径，同时保持终端 Effect 和关键对象不被扩大。

终端工具命中 Effect 节点后，证明器检查 **关键参数完整性与固定参数**。它依据 Effect Contract 取得安全关键字段，并逐项检查候选参数：

```text
required field 缺失
→ ALERT: required_parameter_missing

字段在 IR 中被显式禁止，但调用提供了值
→ ALERT: parameter_not_authorized

字段来自用户字面值
→ 比较实际值与授权值

字段来自运行时 Binding
→ 进入动态求值
```

路径和 URL 等范围型参数使用结构化包含关系。例如，授权目录可以覆盖其子路径，授权 URL 可以覆盖相同域名下的指定子路径；兄弟目录、不同域名或更宽路径范围会形成冲突。

随后，证明器检查 **动态 Binding、来源与版本**：先用已记录的工具返回执行 DAG，再将计算结果与 Agent 的实际参数比较。假设 DAG 规定：

```text
recipients
← project(owner_email)
← select(status = unfinished)
← ToolResult(read_todo)
```

运行时 `read_todo` 返回 Alice 和 Bob 两条记录后，DAG 求值得到：

```text
真实 read_todo 返回
→ select(status = unfinished)
→ project(owner_email)
→ 允许的 recipients = {alice@example.com}
```

候选调用为：

```text
send_email(recipients=["alice@example.com"])
```

证明器比较的是：

```text
DAG 对已观察返回的计算结果
                ↕
Agent 实际提交的参数
```

结果一致时，Binding 得到证明，并记录使用过的 `call_id`、字段路径和 DSL 算子。当前实现对“实际值不在已求得结果中”和“查询因缺少输入而无法完成”均保守输出 `REVIEW: authorized_effect_has_unproved_binding`，因为证明器尚未在所有算子上区分穷尽后的不匹配与不完整求值；固定字面值、显式禁止字段和可判定 Constraint 的冲突则直接输出 `ALERT`。若 Source 关联了持久对象版本，证明器还会检查该版本是否由已授权写入形成。

当前 DAG Evaluator 支持阶段一定义的有限算子：`select / project / join / aggregate / compute / normalize / template`。这些算子由普通程序执行，不调用额外模型。

参数闭合后，证明器检查 **Constraint、对象范围与 Budget**。DAG 中的谓词在真实返回上成立则标记为 `proved`，与证据冲突则输出 `ALERT`，缺少输入则输出 `REVIEW`。对象范围已经在参数比较中一并检查，防止文件、URL 和资源标识符扩展到授权范围之外。

Budget 由运行时账本维护，支持 Effect 总次数和按关键 Binding 计数。例如：

```text
每个 recipients 最多一次
总邮件数最多十次
```

候选调用通过证明后先进入 `pending` 状态；工具成功产生 Effect 后，账本才增加对应计数。失败调用不消费授权，撤销的 Effect 和已经耗尽的 Budget 会在后续调用中直接形成冲突。

## 3. 从证明状态形成判定

阶段二的三种输出由必要授权关系的状态直接决定：

```text
ALLOW
工具角色、关键参数、Binding、Constraint、版本和 Budget 均已闭合。

ALERT
至少一项必要关系与授权存在确定冲突。

REVIEW
尚未发现确定冲突，但至少一项必要关系缺少证明。
```

`REVIEW` 进一步携带问题类型，使后续系统采取不同处理：

```text
semantic_unresolved
有限算子无法判断开放语义关系
→ 阶段三构造局部语义证明

evidence_missing
缺少工具返回、字段、对象版本或参数连接
→ 补充证据；无法补证时阻止执行或请求用户处理

policy_confirmation
用户给外部来源的委托范围不明确
→ 请求用户确认授权边界
```

语义审计只处理 `semantic_unresolved`。缺失事实需要真实工具或环境补充，委托范围则需要可信用户决定。

每次判定还返回结构化证明信息：候选 Effect、发生问题的字段、使用的 Source 调用、执行过的 DSL 算子、字段级证据路径和具体原因。这些信息既用于解释决策，也构成阶段三的最小证据入口。

## 4. 贯穿案例

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

运行时首先执行读取：

```text
Agent → read_todo(用户指定路径)
Gateway → 检查读取来源和路径范围
Tool → 返回 TODO 记录
Gateway → 保存 Observation 与字段级 Fact
```

当 Agent 提出 `send_email` 时，证明过程为：

```text
1. Effect：send_email 对应已授权 external_message
2. 完整性：recipients / subject / body / attachments 均已表达
3. 固定参数：subject 与授权字面值一致，attachments 为空
4. 动态求值：unfinished 记录导出 Alice 及其 task
5. 参数比较：实际 recipients 和 body 与 DAG 结果一致
6. Constraint：Alice 对应记录满足 status=unfinished
7. Budget：Alice 尚未发送，总数未超过十次
8. 结果：ALLOW
```

三个变体展示不同判定来源：

```text
实际收件人为 Bob
→ DAG 只导出 Alice
→ REVIEW: authorized_effect_has_unproved_binding

TODO 返回缺少 status
→ select 无法求值
→ REVIEW: evidence_missing

用户要求联系“最合适的人”，但没有可执行选择条件
→ 候选对象与开放语义之间的关系未决
→ REVIEW: semantic_unresolved
```

**能力边界。** 阶段二能够程序化验证 Effect、工具角色、关键参数、有限数据来源、确定性计算、结构化条件、对象范围、消费预算，以及已接入版本账本的持久状态来源。它不读取 Agent 的隐藏推理，也不依靠攻击关键词；判断依据是可信用户请求编译出的 DAG、部署方契约和主机侧观察到的真实执行证据。

开放语义关系由阶段三补全。证据缺失需要真实工具或环境补证，宽泛委托需要用户确认。版本账本已经能够表达对象版本、父版本、产生写入和写入授权状态；只有完成相应 Agent 环境的持久读写接入后，系统才能端到端验证文件、记忆或工作区版本的形成过程。

阶段二最终形成如下闭环：

```text
真实工具返回
→ 记录 Runtime Observation 与字段级 Fact
→ 绑定 Authorization DAG 的 Source
→ 依次证明工具、参数、来源、条件、版本和预算
→ 与 Agent 候选调用比较
→ ALLOW / ALERT / REVIEW
```
