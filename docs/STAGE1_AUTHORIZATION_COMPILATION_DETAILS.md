# 阶段一：Authorization Compilation

本阶段的目标是将可信用户请求编译为一份路径无关、可在运行时求值的授权规范。实现这一目标需要解决两个问题：一是如何将含有目标、条件、数据来源和委托关系的自然语言转换为结构化规则；二是如何在具体执行路径和部分工具参数尚未确定时，仍然给出足以约束后续行为的授权边界。

我们的关键观察是：用户指令在 Agent 执行语境下，可以统一理解为一条从权限主体和运行时数据通向真实环境效果的授权关系，即谁允许，哪些数据可以参与，数据经过何种计算，在什么条件下、以多少次被使用，最终产生什么真实后果。判断一项行为是否符合这条关系，需要回答五个问题：谁有权补全尚未确定的决策、允许产生什么真实效果、关键参数应当如何形成、授权在什么条件下成立，以及授权可以被使用多少次。

这五个问题直接决定 Authorization IR 的字段，不形成额外的中间数据结构：

```text
Authorization IR
├── delegations：规则集合
│   (授权来源, 可补全字段, 可服务的 Effect)
└── grants：授权项集合
    ├── effect：Effect 描述
    │   (Effect 类型, 实现工具, 安全关键字段)
    ├── bindings：关键字段到参数表达式的映射
    │   critical_field → literal | BindingDSL expression | absent
    ├── constraints：运行时谓词集合
    │   {predicate₁, predicate₂, ...}
    └── budget：Effect 消费策略
        (计数对象, 单对象上限, 总量上限, 有效期)
```

以“读取指定 TODO 文件，给每个未完成任务的负责人发送一次提醒，最多十封”为例：`delegations` 规定 TODO 文件只可补全收件人与正文；`effect` 允许发送提醒邮件；`bindings` 规定收件人和正文从未完成任务中提取；`constraints` 要求记录满足 `status=unfinished`；`budget` 限制每名负责人一次、总数不超过十次。自然语言授权由此直接进入一份包含五类可检查关系的 IR。

## 1. 从授权字段到可执行的动态关系

Authorization IR 给出了授权规则的基本结构，下一步需要使它容纳 Agent 执行中的动态性。动态性主要来自两组信息：一组是动态参数，例如搜索后才能知道的商品 ID、从文件中读取的收件人或创建资源后返回的新 ID；另一组是动态工具路径，例如 Agent 可能采用不同的读取、搜索或中间处理工具完成同一项已授权 Effect。前者要求授权规则能够描述参数的生成过程，后者要求授权规则约束终端效果，同时允许合理的实现路径在运行时展开。

对于动态参数，只记录“允许来自某个文件或某次搜索”并不足以完成授权判断。相同来源可能包含多个候选值，Agent 还需要筛选对象、提取字段、关联记录或选择最优结果。Bindings 因此描述完整的参数生成关系：

```text
工具参数 = 授权数据来源 + 允许的数据变换
```

对于动态参数，我们的关键观察是：参数形成过程与数据库查询具有相同结构，即从一个或多个数据源中选取记录、投影字段、连接对象、聚合集合，再将结果规范化或构造成受限文本。基于关系代数，我们设计了有限的 **Binding DSL**：

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

对于动态工具路径，我们固定终端 Effect 及其关键参数关系，将具体读取、搜索和中间工具留到运行时解析。判断某个新增工具是否服务于授权关系，需要一份独立于 Agent 输出的工具语义依据。我们将其定义为部署方提供的 **Tool Contract**：

```text
Tool Contract Σ(t)
├── kind              read | transform | effect
├── input_fields      工具接收哪些字段
├── output_fields     工具产生哪些字段
├── effect            会造成哪类真实副作用；无副作用则为空
├── critical_fields   哪些输入决定副作用的安全语义
├── requires          调用需要哪些对象或能力
└── provides          调用产生哪些对象或能力
```

例如，`search_hotels` 是无副作用的读取工具，可提供 `name/rating/price`；`reserve_hotel` 产生 `reservation` Effect，`hotel/start_day/end_day` 是其安全关键字段；`create_cart` 则可以提供后续结算所需的 `cart_id`。阶段一使用 Tool Contract 校验 IR 中引用的工具、字段和 Effect，阶段二使用同一契约判断运行时新增工具的输出是否参与已授权 Binding，或其 `provides` 能力是否被后续已授权 Effect 的 `requires` 消费。由此，参数和路径可以动态展开，而终端 Effect、操作对象、来源权限、适用条件和预算仍受 IR 约束。

经过上述表示，一项授权可以理解为带权限约束的声明式查询：Delegation 限定哪些来源可以参与查询，Bindings 定义参数查询程序，Constraints 规定查询结果何时可用，Budget 规定结果可以被消费多少次，Effect 规定查询结果最终可以流向哪类真实副作用。

## 2. 从自然语言生成可信 Authorization IR

IR 字段和 Binding DSL 给出了授权规范的结构，随后需要解决自然语言如何可靠进入该结构的问题。这里存在两类风险：固定规则难以识别“评分最高”对应 `argmax`、“每个未完成任务的负责人”对应 `select + project` 等复杂语义；生成模型又可能遗漏关键参数、引用不存在的来源，或者扩大用户授权。我们的关键观察是，语义理解与安全边界校验可以分离：语义模型负责生成候选结构，部署方控制的工具契约负责判断该结构是否完整、合法。基于这一分工，从自然语言到合法 IR 的转换由语义编译和契约校验两个模块完成，随后再由确定性 Lowerer 生成 DAG：

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

**Constrained Semantic Compiler** 使用语义模型识别用户请求中的委托、Effect、参数关系、条件和预算，并将动态参数翻译为 Binding DSL 表达式。模型只能引用部署方提供的工具、Effect、字段类型、数据来源和 DSL 算子。其输出是一份候选授权程序，运行时放行仍需后续证明：

```text
Authorization IR
├── Delegations
└── Grants
    ├── Effect
    ├── Bindings: critical_field → expression
    ├── Constraints
    └── Budget
```

**Contract-Grounded Validator** 使用上述 Tool Contract 验证候选 IR。它以部署方声明的工具输入、输出、Effect 和安全关键字段为准，检查模型生成的授权结构是否引用了真实存在且类型匹配的工具能力。例如：

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

每个关键参数必须被标记为用户字面值、运行时查询结果、显式禁止或尚无法编译。校验失败时，Validator 将结构化错误返回给语义编译器进行一次受限修复；再次失败则终止编译。该过程保证 IR 相对于用户请求和工具契约具有可检查的结构完整性。

## 3. 从 Authorization IR 到 Authorization DAG

合法 IR 已经表达了用户授权，最后还需要把这份声明式规范转换为运行时可以执行的证明结构。IR 中的嵌套表达式适合生成和类型检查，却不便于绑定真实工具返回、复用共同来源、合并多个参数关系和定位证明失败的位置。我们的关键观察是，参数形成和授权传播天然构成一组有向依赖关系：数据从来源出发，经过确定性变换和条件检查，绑定到 Effect 的关键字段。因此，一个动态酒店参数在 IR 中虽然表现为表达式树：

```text
Project(name)
└── Aggregate(argmax rating)
    └── Select(rating > 4)
        └── ToolResult(search_hotels)
```

从 IR 到 DAG 是确定性的结构转换，类似编译器把表达式语法树展开为数据流图：先为每项 Grant 创建 Effect 节点，再从每个安全关键字段的 Binding 根表达式开始递归展开。遇到数据来源时创建 Source 节点；遇到 DSL 算子时创建 Transform 节点，并用 `data_dep` 连接其输入；表达式根用 `binds(field)` 连接到 Effect；Constraint、Delegation 和版本要求再分别连接到对应路径。相同的来源或子表达式会被合并，因此多个参数可以共享同一份运行时证据。

例如，下面的 IR 表达式：

```text
hotel ← project(name,
          aggregate(argmax rating,
            select(rating > 4,
              tool_result(search_hotels))))
```

按照四条递归规则展开：

```text
tool_result(t)  → Source(t)
op(x)           → Lower(x) ─data_dep→ Transform(op)
binding(f, x)   → Lower(x) ─binds(f)→ Effect
constraint(p)   → Constraint(p) ─guards→ Effect / Transform
```

**Deterministic DAG Lowerer** 据此执行固定的结构转换：

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

语义编译器根据用户请求和工具契约直接生成候选 IR。下面使用紧凑字符串表示 Binding 表达式，实际结构是经过类型约束的嵌套 AST：

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
