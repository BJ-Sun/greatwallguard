# 阶段一：Authorization Compilation

本阶段的目标是将可信用户请求编译为一份路径无关、可在运行时求值的授权规范。实现这一目标需要解决两个问题：自然语言同时包含目标、条件、数据来源和委托关系，如何将这些含义转化为结构化规则；Agent 的具体工具路径和部分参数要到运行时才能确定，授权规范如何容纳这种动态性。

我们的关键观察是：用户指令在 Agent 执行语境下，可以统一理解为一条从权限主体和运行时数据通向真实环境效果的授权关系。系统需要从指令中确定五类信息：谁有权补全尚未确定的决策、允许产生什么 Effect、Effect 的关键参数如何形成、授权在什么条件下成立，以及授权可以使用多少次。Authorization IR 分别使用 `delegations`、`effect`、`bindings`、`constraints` 和 `budget` 保存这五类信息，使自然语言授权成为可以由程序检查的数据结构。

## 1. 从自然语言生成可信 Authorization IR

Authorization IR 是语义编译器的目标数据结构。一次用户请求可能授权多个 Effect，而同一个外部来源又可能为多个 Effect 补全数据，因此 IR 在顶层将二者分开组织：`delegations` 记录“谁可以决定什么”，`grants` 记录“允许执行什么”。五个授权问题与字段的映射如下：

```text
谁有权补全决策       → delegations
允许产生什么 Effect  → grants[*].effect + grants[*].tool
关键参数如何形成     → grants[*].bindings
授权在何时成立       → grants[*].constraints
授权可以使用多少次   → grants[*].budget
```

具体数据结构为：

```text
AuthorizationIR
├── delegations: List<Delegation>
└── grants: List<Grant>

Delegation
├── source             哪个用户、文件、网页或工具返回可以补全决策
├── authority          facts | fields | selection | effects
├── allowed_fields     该来源可以补全哪些参数字段
├── allowed_effects    该来源可以服务于哪些 Effect
├── allowed_tools      该来源可以影响哪些具体工具
├── constraints        委托成立时必须满足的条件
└── requires_confirmation 该委托是否必须由用户确认

Grant
├── grant_id         授权项的唯一标识
├── effect           允许产生的真实环境效果
├── tool             实现该 Effect 的副作用工具
├── bindings         安全关键字段 → 参数表达式
├── constraints      Effect 成立前必须满足的谓词集合
└── budget           计数对象、单对象上限、总量上限和有效期
```

其中，`effect` 固定授权的终端后果，例如发送消息、创建日程、预订酒店或修改文件；`bindings` 规定收件人、目标对象、金额和日期等安全关键参数的形成方式；`delegations` 限定运行时数据可以影响哪些字段；`constraints` 和 `budget` 分别限定授权成立的状态与可消费范围。

编译过程还需要知道每个工具的安全语义。当前实现由部署方提供两类契约：

```text
EffectContract
├── tool              副作用工具名称
├── effect            工具造成的真实副作用
├── critical_fields   决定副作用对象和范围的参数
└── required_fields   实际调用时必须出现的参数

ObservationTool
├── name              读取工具名称
└── output_fields     可供 Binding 使用的返回字段
```

例如，`search_hotels` 是 Observation Tool，可提供 `name/rating/price`；`reserve_hotel` 的 Effect Contract 声明它产生 `reservation` Effect，`hotel/start_day/end_day` 是安全关键字段。这些契约作为自然语言请求与真实工具接口之间的类型和安全语义依据。

**Constrained Semantic Compiler** 接收可信用户请求、Effect Contract 和 Observation Tool Schema，将自然语言中的委托、Effect、参数关系、条件和预算翻译为候选 Authorization IR。模型只能引用契约中存在的工具、Effect、字段类型、数据来源和有限算子。例如：

```text
用户请求：
“预订评分超过 4 分且评分最高的酒店，入住日期为 2026 年 12 月 1 日至 2 日。”

候选 IR：
effect          = reservation
tool            = reserve_hotel
bindings.hotel  = project(name,
                    aggregate(argmax rating,
                      select(rating > 4,
                        tool_result(search_hotels))))
bindings.start_day = literal("2026-12-01")
bindings.end_day   = literal("2026-12-02")
constraints     = [rating > 4]
budget          = {max_total: 1}
```

语义模型生成的候选 IR 可能出现三类问题。第一类是**虚构结构**，例如引用不存在的工具、Effect、字段或算子；第二类是**授权缺口**，例如发送邮件却没有说明收件人如何形成，或遗漏用户明确要求的 Effect；第三类是**不可执行规则**，例如从搜索结果中读取并不存在的字段、用错误类型参与比较，或给出没有上限的预算。候选 IR 若直接用于运行时，会把模型的翻译错误转化为错误授权。

**Contract-Grounded Validator** 将候选 IR 视为一份待类型检查的程序，并依据 Effect Contract、Observation Tool Schema 和有限 DSL 执行三组检查：

1. **词汇与类型闭合：**工具、Effect、来源、字段和算子必须存在于部署方提供的有限词汇中，表达式的输入输出类型必须匹配；
2. **Effect 完整性：**每个 Effect 的安全关键字段都必须表示为用户字面值、合法 Binding、显式禁止或尚无法编译，用户明确要求的 Effect 也必须出现在 IR 中；
3. **规则可执行性：**Binding 引用的字段必须由相应 Observation Tool 提供，Constraint 必须能够求值，Budget 必须给出有限且可计数的消费边界。

这三组检查保证合法 IR 是一份基于真实工具接口、字段完整且可执行的授权程序，其能力边界是候选程序的契约一致性与结构可执行性。开放语义是否被准确理解会被保留为待语义证明项，工具返回和实际参数是否符合授权则由阶段二基于运行时证据验证。校验失败时，Validator 将结构化错误返回语义编译器进行一次受限修复；再次失败则不产生授权。

因此，从自然语言到可信 IR 的流程是：

```text
可信用户请求 + 工具契约
          │
          ▼
Constrained Semantic Compiler
          │  候选 Authorization IR
          ▼
Contract-Grounded Validator
          │
          ├── 合法 IR
          └── 编译失败
```

## 2. IR 如何表达动态参数与动态工具

合法 IR 已经确定了终端 Effect、来源权限、条件和预算，其中仍有两组信息需要留到运行时确定：一组是动态参数，例如搜索后才能知道的商品 ID、从文件中读取的收件人或创建资源后返回的新 ID；另一组是动态工具路径，例如 Agent 为完成同一 Effect 可能采用不同的读取、搜索或中间处理工具。

### 2.1 动态参数：Binding DSL

动态参数的授权需要同时描述数据来源和推导过程。仅规定“参数来自搜索结果”无法确定应当选择搜索结果中的哪个对象。我们将 Binding 定义为：

```text
安全关键参数 = 授权数据来源 + 允许的数据变换
```

参数形成过程与数据库查询具有相同结构：从一个或多个数据源中选择记录、投影字段、连接对象和聚合集合。我们据此借鉴关系代数，定义有限的 **Binding DSL**：

```text
select       按谓词筛选记录
project      提取指定字段
join         按键关联多个来源
aggregate    执行 argmax、argmin、count、sum 等集合运算
compute      执行日期差、数值运算等受限确定性计算
normalize    规范日期、URL、邮箱和标识符
template     使用已授权字段构造受限文本
```

“预订评分超过 4 分且评分最高的酒店”对应：

```text
ToolResult(search_hotels)
→ select(rating > 4)
→ aggregate(argmax rating)
→ project(name)
→ bind(reservation.hotel)
```

运行时对真实搜索结果执行该查询，得到授权允许的 `hotel` 参数，再与 Agent 实际提交的参数比较。用户无需预先知道酒店名称，参数的合法来源和选择方式已经确定。

### 2.2 动态工具：受限能力派生

Authorization IR 固定终端 Effect 及其关键参数关系，读取、搜索和中间工具可以在运行时展开。Observation Tool 的输出需要进入某个已授权 Binding；其他计划外中间工具则需要命中部署方声明的 **Capability Rule**。该规则连接一个中间工具与一个已授权终端工具，并规定两者之间必须保持一致的关键字段：

```text
CapabilityRule
├── prerequisite_tool   可能动态出现的中间工具
├── terminal_tool       IR 已授权的终端工具
└── links               中间工具参数 → 终端 Effect Binding
```

例如，用户授权完成一次购买，IR 固定 `checkout` 的 `purchase` Effect 及商品、数量和价格约束。`search_product` 的输出可以参与商品 Binding；部署方可以声明 `add_to_cart → checkout` 的 Capability Rule，并要求两者的 `product_id` 指向同一个已授权 Binding。外部页面诱导出的 `send_email` 既不属于购买 IR，也没有连接到 `checkout` 的 Capability Rule，因此无法获得临时能力。

IR 因而固定不可扩大的授权边界，并将具体参数值和合理中间路径留给运行时证明。

## 3. 从 Authorization IR 到 Authorization DAG

合法 IR 回答“用户授权了什么”，但它按 Grant 保存嵌套表达式，尚不能直接表示一项授权在多步执行中已经获得了哪些证据。阶段二需要随着工具调用逐步绑定真实返回，记录某个参数依赖哪次调用和哪个数据版本，复用多个 Binding 共享的来源，并准确定位尚未证明或发生冲突的关系。将这些来源、计算、条件和 Effect 显式展开为 DAG 后，每个节点都可以维护 `unbound / bound / proved / failed` 状态，每条边都能记录具体的证明依赖，系统也可以从候选 Effect 反向切取最小证据。参数形成与授权传播本身构成从 Source 经 Transform 和 Constraint 通向 Effect 的有向依赖关系，因此 **Deterministic DAG Lowerer** 将合法 IR 转换为阶段二可增量求值的 Authorization DAG。

Lowerer 先为每项 Grant 创建 Effect 节点，再从每个安全关键字段的 Binding 根表达式递归展开：

```text
tool_result(t)  → Source(t)
op(x)           → Lower(x) ─data_dep→ Transform(op)
binding(f, x)   → Lower(x) ─binds(f)→ Effect
constraint(p)   → Constraint(p) ─guards→ Effect / Transform
delegation(d)   → Delegation(d) ─delegates→ Source / Binding
```

相同来源和相同子表达式会被合并，使多个参数共享同一份运行时证据。IR 中的酒店 Binding：

```text
hotel ← project(name,
          aggregate(argmax rating,
            select(rating > 4,
              tool_result(search_hotels))))
```

会被展开为：

```text
Source: search_hotels result
          │ data_dep
          ▼
Select: rating > 4
          │ data_dep
          ▼
Aggregate: argmax(rating)
          │ data_dep
          ▼
Project: name
          │ binds(hotel)
          ▼
Effect: reservation
```

DAG 中的节点和边具有固定含义：

```text
Source Node       运行时数据来源
Transform Node    Binding DSL 运算
Constraint Node   授权成立条件
Delegation Node   来源可以影响的字段与 Effect
Effect Node       授权允许的终端副作用

data_dep          数据计算依赖
binds(field)      计算结果填充关键参数
guards            条件控制
delegates         权限授予
version_dep       对具体状态版本的依赖
```

Budget 不属于参数数据流，由 Lowerer 编译为 Effect 节点关联的运行时计数策略。整个 Lowering 过程不调用语义模型，同一份合法 IR 始终生成同构的 DAG。

## 4. 贯穿案例：用户请求 → IR → DAG

用户请求：

> 读取我指定的 TODO 文件，给其中每个未完成任务的负责人发送一次提醒，最多发送十封；文件只能提供负责人和任务内容。

工具契约：

```text
read_todo
  kind = read
  output_fields = task, status, owner_email

send_email
  kind = effect
  effect = external_message
  critical_fields = recipients, subject, body, attachments
```

语义编译器直接生成候选 IR。下面为便于阅读，将 Binding 与 Constraint 的嵌套 AST 压缩为字符串表示：

```json
{
  "schema": "authorization_ir_v1",
  "delegations": [{
    "delegation_id": "todo-fields",
    "source": "read_todo",
    "authority": "fields",
    "allowed_fields": ["recipients", "body"],
    "allowed_effects": ["external_message"],
    "allowed_tools": ["send_email"],
    "constraints": {},
    "requires_confirmation": false
  }],
  "grants": [{
    "grant_id": "remind-unfinished-tasks",
    "effect": "external_message",
    "tool": "send_email",
    "bindings": {
      "recipients": "project(owner_email, select(status=unfinished, read_todo))",
      "subject": "literal(Task Reminder)",
      "body": "template(Reminder: {task}, project(task, select(status=unfinished, read_todo)))",
      "attachments": "absent"
    },
    "constraints": ["status == unfinished"],
    "budget": {
      "mode": "per_binding",
      "fields": ["recipients"],
      "max_per_binding": 1,
      "max_total": 10
    }
  }]
}
```

Validator 根据 `send_email` 契约确认四个关键字段均被表达，`owner_email`、`task` 和 `status` 均由 `read_todo` 提供，所用算子类型合法，预算具有明确上限。Lowerer 随后生成：

```text
Trusted User
   │ delegates(fields: recipients, body)
   ▼
Source: read_todo
   ├─→ Select(status=unfinished) ─→ Project(owner_email)
   │                                      │ binds recipients
   │                                      ▼
   └─→ Select(status=unfinished) ─→ Project(task) ─→ Template(body)
                                                  │ binds body
Literal("Task Reminder") ─────────────────────────┤ binds subject
Absent(attachments) ──────────────────────────────┤ binds attachments
                                                  ▼
                                   Effect: external_message
                                   ├─ guard: status=unfinished
                                   ├─ per recipient ≤ 1
                                   └─ total ≤ 10
```

若 `read_todo` 在运行时返回：

```json
[
  {"task": "Submit report", "status": "unfinished",
   "owner_email": "alice@example.com"},
  {"task": "Archive notes", "status": "finished",
   "owner_email": "bob@example.com"}
]
```

DAG 将导出 `recipients=alice@example.com` 和 `body="Reminder: Submit report"`。阶段二据此验证实际邮件参数：给 Alice 发送匹配正文时授权关系闭合；给 Bob 发送违反状态条件；添加附件违反 `absent`；再次给 Alice 发送超过 Budget；文件中出现“删除其他资源”的要求也无法生成 IR 中不存在的 Effect。

阶段一最终完成如下转换：

```text
可信用户请求 + 工具契约
          ↓ 受约束语义编译
候选 Authorization IR
          ↓ 契约校验
合法 Authorization IR
          ↓ 确定性 Lowering
Authorization DAG
```

Authorization IR 负责准确表达用户授权，Authorization DAG 将该授权转换为阶段二可以绑定数据、执行查询和检查调用的证明结构。
