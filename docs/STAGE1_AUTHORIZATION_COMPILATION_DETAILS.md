# 阶段一：将自然语言编译为 Authorization DAG

阶段一要解决的不是“预测 Agent 将调用哪些工具”，而是：**在具体执行路径和参数尚未确定时，先建立一份可供运行时验证的用户授权。**

为此，我们提出 **Authorization Compilation** 方法：将可信用户请求编译为一张路径无关、可在运行时实例化和校验的 Authorization DAG。该方法包含三个依次执行的模块：

```text
① Constrained Semantic Compiler
   可信用户请求 → 候选 Authorization IR

② Contract-Grounded Validator
   工具契约 → 类型检查、完整性检查与一次受限修复

③ Deterministic DAG Lowerer
   合法 IR → Authorization DAG
```

三个模块分别解决自然语言理解、生成式输出约束和运行时可验证表示问题。阶段一最终输出一张待运行时数据实例化的授权证明模板。

整个阶段按照下面的逻辑逐层构造：

```text
自然语言用户请求
        ↓
识别授权五元组
        ↓
将动态参数表示为有限关系查询
        ↓
LLM 生成候选 Authorization IR
        ↓
工具契约进行类型与完整性检查
        ↓
确定性 Lowering
        ↓
Authorization DAG
```

这里需要区分授权边界与执行计划。阶段一静态编译的是用户允许的**终端效果及其不变量**，而不是 Agent 必须照抄的完整工具序列：

```text
阶段一固定：允许产生什么终端 Effect、关键参数如何形成、
            哪些来源可以补全参数、条件和预算是什么。

阶段一不固定：具体参数值、读取工具的等价实现、
              为完成终端效果临时需要的中间工具及调用顺序。
```

当前 IR 中的 `tool` 表示由工具契约绑定的终端 Effect 实现，而不是整条计划的工具白名单。读取工具和中间工具不需要全部提前写入计划，阶段二可分别通过来源能力和受限能力派生进行验证。因此，阶段一留下两类运行时变量：Binding 中尚未出现的参数值，以及尚未确定的实现路径；前者由数据查询实例化，后者由阶段二在不扩大终端授权的前提下验证。

## 1. 核心观察与授权定义

用户请求无法直接与工具调用比较。相同的行为在不同语境下可能具有不同权限，而自然语言中还混合了目标、条件、数据来源和委托关系。因此，我们首先需要确定：一次工具行为获得用户授权，最少需要描述哪些信息？

**Key Insight.** 用户的一段自然语言指令可以被规范化为一条从权限主体、运行时数据和计算过程通向真实环境效果的授权链：谁有权补全决策，哪些数据可以参与，数据经过何种计算形成工具参数，授权在什么条件下、以多少次被消费，以及最终允许产生什么效果。

基于这一观察，我们定义了面向工具型 Agent 的**授权五元组** \(A=\langle D,E,B,C,Q\rangle\)，将一项用户授权分解为五个部分：

```text
Delegation   谁可以补全运行时尚未确定的决策
Effect       允许产生什么真实环境变化
Bindings     效果关键参数如何形成
Constraints  授权成立时必须满足什么条件
Budget       授权可以被消费多少次、持续多久
```

五元组定义了授权需要覆盖的语义，并将开放的自然语言意图收敛为有限授权接口。其中，Effect、Constraints 和 Budget 固定终端边界，Bindings 允许参数延迟确定，Delegation 则限定哪些运行时来源可以补全参数，或在用户明确授权时补充效果。但它还没有解决动态参数如何表达。

## 2. 从参数集合到参数生成关系

一种简单做法是把 Bindings 表示为允许的参数值：

```text
recipient = Alice
file = report.md
```

但动态任务中的许多值在用户发出指令时尚不存在。例如：

- 酒店名称需要由搜索结果确定；
- 收件人需要从 TODO 文件中提取；
- 商品 ID 需要根据价格和评分筛选；
- 新文件 ID 只有创建文件后才会返回。

因此，我们发现 Bindings 不能只是静态参数列表，而必须描述：

```text
参数 ← 数据来源 + 推导过程
```

也就是最终参数允许从哪些数据中，经过什么计算得到。

相同的工具和终端效果，可能因为收件人、目标对象、金额或状态版本不同，分别构成正常行为或越权行为。因此，参数值是否“出现过”并不足够；系统必须保留从授权数据来源到实际工具参数的完整推导关系。

我们将 Binding 定义为从安全关键字段到参数生成表达式的映射。每个表达式说明参数由哪个授权来源、经过哪些确定性变换产生。这使 Bindings 从“值集合”提升为“参数查询程序”。

如果允许 LLM 用任意自然语言描述参数生成过程，运行时仍然无法稳定执行和验证。例如：

```text
选择一个合适的酒店
找到真正需要联系的人
按照文件要求处理
```

这些描述没有明确的计算语义。

我们的观察是：Agent 从用户消息、文件、网页和工具返回中提取信息并形成工具参数时，其中可确定、可程序化的部分，本质上可以表示为一次声明式数据查询：

```text
从哪些数据中
筛选哪些记录
提取哪些字段
关联哪些来源
选择哪个对象
进行什么确定性计算
```

基于这一数据查询视角，我们借鉴关系代数，设计了有限的 **Binding DSL**：

```text
select       按条件筛选对象
project      提取字段
join         关联多个来源
aggregate    最大、最小、计数和求和
compute      执行受限确定性计算
normalize    规范日期、URL和标识符
template     使用已授权字段构造有限文本
```

例如：

> 预订评分超过 4 分且评分最高的酒店。

可以表示为：

```text
search_hotels
→ select(rating > 4)
→ aggregate(argmax rating)
→ project(name)
→ bind reservation.hotel
```

用户不需要提前知道酒店名称，但必须提前限定酒店名称的合法生成过程。

至此，授权的五个部分可以被统一理解为：

```text
Delegation   限定哪些数据源有权参与查询
Bindings     定义参数查询过程
Constraints  限定查询结果可以在什么状态下使用
Budget       限定查询结果可以被消费多少次
Effect       限定查询结果最终可以流向什么副作用
```

由此，用户授权被表示为一份“带权限和消费约束的声明式查询”。Binding DSL 将动态任务中的可程序化部分限制在少量通用算子内，使后续系统能够执行相同查询并验证真实参数。

## 3. Authorization Compilation

有限 DSL 解决了“如何表示”的问题，但还需要解决“如何从自然语言生成”的问题。

纯规则方法难以稳定识别：

- “评分最高”对应 `argmax`；
- “每个未完成任务的负责人”对应 `select + project`；
- “入住一晚”对应日期计算；
- “根据 Taylor 的邮件创建日程”包含字段级委托；
- “完成邮件中的任务”则可能包含效果级委托。

因此，Authorization Compilation 的第一个模块是 **Constrained Semantic Compiler**。它使用 LLM 作为语义编译前端，将可信用户请求翻译为候选 Authorization IR：

```text
Authorization IR
├── Delegations
└── Grants
    ├── Effect
    ├── Bindings: field → expression
    ├── Constraints
    └── Budget
```

这里的设计原则是：自然语言理解需要生成模型，但安全边界不能由生成模型自由定义。因此，LLM 只负责将自然语言翻译为有限结构，不负责决定某次调用是否放行，也不能创造新的工具、效果或运算符。该模块的输出是一份带类型字段的候选授权程序，而不是安全决策。

但这又带来下一问题：如何防止 LLM 遗漏关键参数或生成不存在的授权？

生成模型可能遗漏关键参数、引用不存在的工具和字段，或将外部内容中的动作误认为用户授权。因此，候选 IR 不能直接进入运行时。

为此，第二个模块 **Contract-Grounded Validator** 为每个工具引入部署方控制的契约。其依据是：工具 schema 只描述参数的语法，无法说明哪些字段决定安全效果；因此需要在 schema 之上补充稳定的 Effect Contract。

副作用工具声明：

```text
工具会产生什么 Effect；
哪些参数决定其安全语义；
哪些字段是实际调用所必需的。
```

读取工具声明：

```text
工具可以提供哪些字段；
这些字段属于什么数据来源。
```

例如：

```text
reserve_hotel
  effect = reservation
  critical_fields = hotel, start_day, end_day

search_hotels
  output_fields = name, rating, price
```

Validator 随后执行：

1. 工具和 Effect 是否存在于契约中；
2. 所有安全关键参数是否都被表达；
3. 数据来源和字段是否属于已知 schema；
4. 使用的关系算子是否合法；
5. Constraints 是否可以执行；
6. Budget 是否具有有限边界；
7. 用户明确要求的 Effect 是否被遗漏。

每个关键字段都必须被表示为用户字面值、运行时来源及查询表达式、显式未授权或尚无法确定，不能被静默省略。

LLM 输出因而只是一份候选程序。只有经过类型检查和完整性检查的 IR 才能进入后续阶段。校验失败时，Validator 将具体错误返回给编译前端，最多进行一次受限修复；仍不合法则编译失败，而不是退化为宽泛白名单。该模块保证的是相对于工具契约的结构完整性，而非声称完全理解用户语义。

校验后的 IR 中，每个 Binding 是一棵嵌套表达式树。例如：

```text
Project(name)
└── Aggregate(argmax rating)
    └── Select(rating > 4)
        └── ToolResult(search_hotels)
```

表达式树适合生成和校验，但运行时需要：

- 绑定具体工具返回；
- 汇合多个参数来源；
- 复用共同数据来源；
- 定位证明在哪一步失败；
- 从最终 Effect 反向切取最小证据。

表达式树适合描述单个参数的计算，但运行时授权需要同时合并多个参数、条件、委托和预算，并定位每项证明的成功或失败。因此，第三个模块 **Deterministic DAG Lowerer** 将经过验证的表达式 AST 按照固定规则转换为 Authorization DAG。Lowerer 不再调用 LLM，使同一份合法 IR 始终产生同构的证明结构：

```text
ToolResult(search_hotels)
        │ data_dep
        ▼
Select(rating > 4)
        │ data_dep
        ▼
Aggregate(argmax rating)
        │ data_dep
        ▼
Project(name)
        │ binds(hotel)
        ▼
Effect(reservation)
```

生成规则由各 IR 构件的证明职责决定：

```text
数据来源          → Source Node
关系运算          → Transform Node
执行条件          → Constraint Node
终端副作用        → Effect Node
权限转移          → Delegation Node

计算依赖          → data_dep
参数填充          → binds
条件控制          → guards
权限授予          → delegates
状态版本依赖      → version_dep
```

Budget 不是参数数据流，而是 Effect 的状态化消费规则，由运行时账本维护。

DAG 因此不是自然语言的可视化结果，而是一张可执行的授权证明模板：

- 叶节点规定证明可以从哪些可信值或运行时来源开始；
- 中间节点规定允许进行哪些确定性计算；
- Constraint 和 Delegation 限定数据何时以及凭什么可以继续传播；
- Effect 是证明的终点；
- Budget 限定同一证明可以被使用多少次。

三个模块合在一起形成如下编译算法：

```text
Algorithm: CompileAuthorization(U, Σ)

Input:
  U  可信用户请求
  Σ  Effect / Observation 工具契约

Output:
  GA Authorization DAG，或编译失败

1. 将 U、有限 Binding DSL 和 Σ 交给 Semantic Compiler；
2. 生成候选 Authorization IR；
3. Validator 检查 Effect、关键字段、来源、算子、条件和预算；
4. 若失败，携带确定性错误进行最多一次修复并重新验证；
5. 创建可信用户根节点和经过验证的 Delegation 节点；
6. 对每个 Grant 创建 Effect 节点；
7. 递归 Lower 每个 Binding 表达式并连接 binds 边；
8. Lower 每个 Constraint 并连接 guards 边；
9. 将 Budget 编译为 Effect 的运行时消费策略；
10. 检查图无环、关键字段完整和所有来源均有契约；
11. 返回 GA；任何检查失败均不产生授权。
```

该算法将 LLM 限定在第一步的语义翻译中；IR 验证、图生成和图不变量检查均由确定性程序完成。

## 4. 贯穿案例：从用户指令到 DAG

最后使用一个案例集中展示五元组、IR 和 DAG 的实际结构。

### 4.1 用户请求和工具环境

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

### 4.2 五元组

\[
A=\langle D,E,B,C,Q\rangle
\]

```text
D：TODO 文件具有字段级委托，
   只允许参与填写 recipients 和 body，
   不能新增其他 Effect。

E：允许通过 send_email 产生 external_message。

B：recipients ← project(owner_email,
                        select(status=unfinished, read_todo))
   subject    ← literal("Task Reminder")
   body       ← template("Reminder: {task}",
                        project(task,
                        select(status=unfinished, read_todo)))
   attachments← absent(explicit_forbid=true)

C：所使用记录的 status == unfinished。

Q：按 recipients 计数，每个值最多一次，总数最多十次。
```

### 4.3 Authorization IR

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
    "requires_confirmation": false
  }],
  "grants": [{
    "grant_id": "remind-unfinished-tasks",
    "tool": "send_email",
    "effect": "external_message",
    "bindings": {
      "recipients": {
        "op": "project",
        "field": "owner_email",
        "source": {
          "op": "select",
          "field": "status",
          "comparator": "eq",
          "value": "unfinished",
          "source": {"op": "tool_result", "tool": "read_todo"}
        }
      },
      "subject": {"op": "literal", "value": "Task Reminder"},
      "body": {
        "op": "template",
        "format": "Reminder: {task}",
        "source": {
          "op": "project",
          "field": "task",
          "source": {
            "op": "select",
            "field": "status",
            "comparator": "eq",
            "value": "unfinished",
            "source": {"op": "tool_result", "tool": "read_todo"}
          }
        }
      },
      "attachments": {"op": "absent", "explicit_forbid": true}
    },
    "constraints": [{
      "left": {
        "op": "project",
        "field": "status",
        "source": {"op": "tool_result", "tool": "read_todo"}
      },
      "comparator": "eq",
      "right": {"op": "literal", "value": "unfinished"}
    }],
    "budget": {
      "mode": "per_binding",
      "fields": ["recipients"],
      "max_per_binding": 1,
      "max_total": 10
    }
  }]
}
```

### 4.4 Lowering 后的 DAG

```text
Trusted User
   │ delegates(fields: recipients/body)
   ▼
Delegation: read_todo

read_todo ─→ select(status=unfinished) ─→ project(owner_email)
    │                                                │
    │                                                │ binds recipients
    │                                                ▼
    └─→ select(status=unfinished) ─→ project(task) → template(body)
                                                    │ binds body
"Task Reminder" ───────────────────────────────────┤ binds subject
absent(attachments) ────────────────────────────────┤ binds attachments
                                                    ▼
                                      Effect: external_message
                                      ├─ guard: status=unfinished
                                      ├─ per recipient ≤ 1
                                      └─ total ≤ 10
```

初始图中，用户字面值和 `absent` 节点为 `proved`，`read_todo` 为 `unbound`。运行时读取 TODO 后，阶段二将实际 observation 绑定到 Source，执行 `select`、`project` 和 `template`，再将求值得到的合法参数与实际 `send_email` 参数比较。

例如，若 TODO 返回：

```json
[
  {"task": "Submit report", "status": "unfinished",
   "owner_email": "alice@example.com"},
  {"task": "Archive notes", "status": "finished",
   "owner_email": "bob@example.com"}
]
```

图只会导出：

```text
recipients = alice@example.com
body = "Reminder: Submit report"
```

给 Alice 发送匹配正文时，数据流、权限流、条件和预算闭合；给 Bob 发送会违反状态约束；添加附件会违反显式 `absent`；文件要求删除其他对象会超出字段级委托；再次给 Alice 发送会超过 Budget。

## 5. 阶段一的完整闭环

阶段一最终完成如下数据结构变化：

```text
自然语言字符串
→ 授权五元组
→ Binding 查询表达式
→ JSON Authorization IR
→ 类型检查后的表达式 AST
→ Authorization DAG
→ 等待运行时证据绑定的授权证明模板
```

从研究贡献看，这一阶段形成了一个闭环：我们首先发现固定调用路径不能表达动态授权，进而定义授权五元组；基于关系代数和编译器 IR 思想设计有限 Binding DSL；再提出由语义编译、契约验证和确定性 Lowering 构成的 Authorization Compilation 算法。其直接能力不是提前预测 Agent 的完整计划，而是为运行时的每个实际效果提供一张可求值、可追溯、可拒绝的授权证明模板。

每一项设计都解决上一层遗留的问题：

| 上一层问题 | 下一项设计 |
|---|---|
| 自然语言不能直接审计 | 授权五元组 |
| 动态参数无法提前给值 | Binding 生成关系 |
| 开放生成关系无法执行 | 有限关系 DSL |
| 规则难以理解复杂语言 | LLM 语义编译 |
| LLM 可能遗漏或越权 | 工具契约和确定性验证 |
| AST 不适合运行时证明 | Lowering 为 Authorization DAG |

阶段一的输出不是对 Agent 执行路径的预测，而是：**一张描述哪些来源经过哪些计算，在什么权限、状态和消费边界内，可以生成哪些工具参数并流向哪些真实副作用的授权查询图。**
