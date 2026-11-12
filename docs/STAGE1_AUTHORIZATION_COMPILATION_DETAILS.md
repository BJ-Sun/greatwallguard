# 阶段一：Authorization Compilation

阶段一将可信用户请求编译为一份路径无关、可在运行时求值的授权规范。Agent 的具体执行路径和部分工具参数通常要等到工具返回后才能确定，但任何产生真实环境影响的行为都必须回答五个授权问题：谁有权补全尚未确定的决策、允许产生什么真实效果、关键参数应当如何形成、行为需要满足什么条件，以及授权可以被使用多少次。我们据此将一项用户授权形式化为五元组：

\[
A=\langle D,E,B,C,Q\rangle
\]

```text
Delegation   D：谁有权补全运行时决策，以及可以补全哪些字段
Effect       E：允许产生什么真实环境变化
Bindings     B：Effect 的关键参数应当如何形成
Constraints  C：授权成立时必须满足什么状态和条件
Budget       Q：授权可以使用多少次、持续多久
```

这五个分量分别覆盖授权判断中的权限主体、终端后果、数据形成、适用条件和消费范围。以“读取指定 TODO 文件，给每个未完成任务的负责人发送一次提醒，最多十封”为例：TODO 文件可以补全收件人与正文，但无权提出新的任务；允许的 Effect 是发送提醒邮件；收件人和正文需要从未完成任务中提取；邮件只能针对 `status=unfinished` 的记录；每名负责人最多收到一次，总数不超过十次。五元组由此固定了用户授权的外部边界。

## 1. 从授权五元组到可执行的动态关系

五元组可以描述 Effect、来源权限、适用条件和使用次数，其中仍有两类信息需要留到运行时确定。第一类是动态参数，例如搜索后才能知道的商品 ID、从文件中读取的收件人或创建资源后返回的新 ID；第二类是实现路径，例如 Agent 可能采用不同的读取、搜索或中间处理工具完成同一项已授权 Effect。

对于动态参数，只记录“允许来自某个文件或某次搜索”并不足以完成授权判断。相同来源可能包含多个候选值，Agent 还需要筛选对象、提取字段、关联记录或选择最优结果。Bindings 因此描述完整的参数生成关系：

```text
工具参数 = 授权数据来源 + 允许的数据变换
```

我们观察到，这类参数形成过程与数据库查询具有相同结构：从一个或多个数据源中选取记录、投影字段、连接对象、聚合集合，再将结果规范化或构造成受限文本。基于关系代数，我们设计了有限的 **Binding DSL**：

```text
select       按谓词筛选记录
project      提取指定字段
join         按键关联多个来源
aggregate    执行 argmax、argmin、count、sum 等集合运算
compute      执行日期差、数值运算等受限确定性计算
normalize    规范日期、URL、邮箱和标识符
template     使用已授权字段构造受限文本
```

例如，“预订评分超过 4 分且评分最高的酒店”被表示为：

```text
ToolResult(search_hotels)
→ select(rating > 4)
→ aggregate(argmax rating)
→ project(name)
→ bind(reservation.hotel)
```

用户无需提前给出酒店名称，授权规范仍然明确限定了酒店名称的来源和选择方法。运行时可以对真实搜索结果执行同一查询，再将查询结果与 Agent 实际提交的 `hotel` 参数比较。

动态工具路径采用相同的边界原则处理。阶段一固定终端 Effect 及其关键参数关系，不枚举唯一工具序列；读取、搜索和中间工具在阶段二根据工具契约判断其输出是否参与某个已授权 Binding，或其能力是否是实现已授权 Effect 的必要中间步骤。这样，动态性被限制在“如何取得和处理已授权数据”以及“如何实现已授权 Effect”之内，运行时数据不能据此新增终端 Effect、扩大操作对象或改变预算。

经过上述表示，五元组可以统一理解为一项带权限约束的声明式查询：Delegation 限定哪些来源可以参与查询，Bindings 定义参数查询程序，Constraints 规定查询结果何时可用，Budget 规定结果可以被消费多少次，Effect 规定结果最终可以流向哪类真实副作用。

## 2. 从自然语言生成可信 Authorization IR

五元组和 Binding DSL 给出了授权规范的目标结构，下一步是把自然语言请求可靠地转换为该结构。固定规则难以稳定识别“评分最高”对应 `argmax`、“每个未完成任务的负责人”对应 `select + project`，也难以区分文件只提供字段值还是被用户授权提出新的 Effect。从自然语言到合法 IR 的转换因此由语义编译和契约校验两个职责分离的模块完成，随后再由确定性 Lowerer 生成 DAG：

```text
可信用户请求 + 工具契约
          │
          ▼
Constrained Semantic Compiler
          │  候选 Authorization IR
          ▼
Contract-Grounded Validator
          │  合法 Authorization IR
          ▼
Deterministic DAG Lowerer
          │
          ▼
Authorization DAG
```

**Constrained Semantic Compiler** 使用语义模型识别用户请求中的五元组，并将动态参数翻译为 Binding DSL 表达式。模型只能引用部署方提供的工具、Effect、字段类型、数据来源和 DSL 算子。其输出是一份候选授权程序，运行时放行仍需后续证明：

```text
Authorization IR
├── Delegations
└── Grants
    ├── Effect
    ├── Bindings: critical_field → expression
    ├── Constraints
    └── Budget
```

**Contract-Grounded Validator** 使用部署方控制的工具契约验证候选 IR。副作用工具契约声明工具产生的 Effect、决定安全语义的关键参数和调用所需字段；读取工具契约声明可提供的数据字段及其来源类型。例如：

```text
reserve_hotel
  effect = reservation
  critical_fields = hotel, start_day, end_day

search_hotels
  output_fields = name, rating, price
```

Validator 依次检查：

1. IR 引用的工具和 Effect 是否存在；
2. Effect 的所有安全关键参数是否都有 Binding；
3. 数据来源和字段是否属于已知工具输出；
4. Binding 是否只使用有限 DSL 算子且类型匹配；
5. Constraints 是否可以执行；
6. Budget 是否具有明确边界；
7. 用户明确要求的 Effect 是否被遗漏。

每个关键参数必须被标记为用户字面值、运行时查询结果、显式禁止或尚无法编译，不能被静默省略。校验失败时，Validator 将结构化错误返回给语义编译器进行一次受限修复；再次失败则终止编译。该过程保证 IR 相对于用户请求和工具契约具有可检查的结构完整性。

## 3. 从 Authorization IR 到 Authorization DAG

合法 IR 已经表达了用户授权，但其嵌套表达式不便于运行时绑定真实工具返回、复用共同来源、合并多个参数关系和定位证明失败的位置。例如，一个动态酒店参数在 IR 中是一棵表达式树：

```text
Project(name)
└── Aggregate(argmax rating)
    └── Select(rating > 4)
        └── ToolResult(search_hotels)
```

**Deterministic DAG Lowerer** 按固定规则将合法 IR 转换为 Authorization DAG：

```text
数据来源          → Source Node
关系运算          → Transform Node
执行条件          → Constraint Node
权限转移          → Delegation Node
终端副作用        → Effect Node

计算依赖          → data_dep
参数填充          → binds
条件控制          → guards
权限授予          → delegates
状态版本依赖      → version_dep
```

酒店参数由此生成下面的证明路径：

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

图中的叶节点规定参数可以从哪些可信字面值或运行时来源开始，中间节点规定允许执行哪些确定性变换，Delegation 和 Constraint 限定数据凭什么以及何时可以继续传播，Effect 是授权证明的终点。Budget 作为 Effect 的状态化消费规则由运行时账本维护。Lowerer 不调用语义模型，因此同一份合法 IR 始终产生同构的证明结构。

完整编译过程可以写为：

```text
CompileAuthorization(U, Σ):
  1. SemanticCompiler(U, Σ, BindingDSL) → candidate IR
  2. Validator(candidate IR, Σ) → valid IR or typed errors
  3. 对一次修复后的 IR 重新执行 Validator
  4. Lowerer(valid IR) → Authorization DAG
  5. 检查 DAG 无环、关键字段完整、所有来源均有契约
  6. 返回 DAG；任一必要检查失败则不产生授权
```

其中，语义模型只参与自然语言到候选 IR 的翻译；IR 验证、DAG 生成和图不变量检查均由确定性程序完成。

## 4. 贯穿案例：从用户请求到 Authorization DAG

用户请求：

> 读取我指定的 TODO 文件，给其中每个未完成任务的负责人发送一次提醒，最多发送十封；文件只能提供负责人和任务内容。

工具契约：

```text
read_todo
  output_fields = task, status, owner_email

send_email
  effect = external_message
  critical_fields = recipients, subject, body, attachments
```

该请求首先形成授权五元组：

```text
D：read_todo 只可补全 recipients 和 body，不能新增 Effect
E：允许 send_email 产生 external_message
B：recipients ← project(owner_email,
                        select(status=unfinished, read_todo))
   subject    ← literal("Task Reminder")
   body       ← template("Reminder: {task}",
                        project(task,
                        select(status=unfinished, read_todo)))
   attachments← absent
C：所使用记录的 status == unfinished
Q：每个 recipient 最多一次，总数最多十次
```

语义编译器将其转换为候选 IR，下面省略重复的嵌套结构，仅展示关键字段：

```json
{
  "delegations": [{
    "source": "read_todo",
    "allowed_fields": ["recipients", "body"],
    "allowed_effects": ["external_message"]
  }],
  "grants": [{
    "tool": "send_email",
    "effect": "external_message",
    "bindings": {
      "recipients": "project(owner_email, select(status=unfinished, read_todo))",
      "subject": "literal(Task Reminder)",
      "body": "template(Reminder: {task}, project(task, select(status=unfinished, read_todo)))",
      "attachments": "absent"
    },
    "constraints": ["status == unfinished"],
    "budget": {"per_recipient": 1, "max_total": 10}
  }]
}
```

Validator 根据 `send_email` 契约确认四个关键参数均有定义，`owner_email`、`task` 和 `status` 均由 `read_todo` 提供，所用算子类型合法，预算具有明确上限。Lowerer 随后生成：

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

若运行时 `read_todo` 返回：

```json
[
  {"task": "Submit report", "status": "unfinished",
   "owner_email": "alice@example.com"},
  {"task": "Archive notes", "status": "finished",
   "owner_email": "bob@example.com"}
]
```

该 DAG 将导出 `recipients=alice@example.com` 和 `body="Reminder: Submit report"`。阶段二可以据此验证实际邮件参数：给 Alice 发送匹配正文时授权关系闭合；给 Bob 发送违反状态条件；添加附件违反 `absent`；再次给 Alice 发送超过 Budget；文件中出现“删除其他资源”的要求也无法新增授权图中不存在的 Effect。

阶段一至此完成如下数据结构变换：

```text
可信自然语言请求
      ↓ 受约束语义翻译
候选 Authorization IR
      ↓ 工具契约校验
合法 Authorization IR
      ↓ 确定性 Lowering
Authorization DAG
```

Authorization DAG 固定用户授权的终端边界和参数形成关系，同时保留具体参数值与合理中间工具路径的运行时动态性；它是阶段二执行确定性授权证明的输入。
