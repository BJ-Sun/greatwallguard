# Progressive Authorization Proof：新 Benchmark 适配成本分析

## 1. 要量化的不是“跑通代码”，而是方法依赖多少新知识

将方法迁移到一个新 benchmark 时，需要区分两类成本。**方法适配成本**决定防御能否在新 Agent 上运行，包括工具语义、动态依赖和执行事件的接入；**评测适配成本**只用于计算实验指标，包括 case 读取、正常/攻击标签和 oracle 对齐。后者可能代码很多，但真实部署并不需要，不能据此判断方法是否泛用。

更重要的是，现有三个 benchmark 与方法共同演进，历史代码量混入了方法研发成本。因此，当前不能用“曾经新增多少行代码”直接证明泛用性。合理的分析对象是：冻结现有 DSL、编译器和运行时后，一个新 benchmark 至少需要提供多少 benchmark-specific 声明；任何根据测试结果增加的新算子、新 Effect 或特殊规则，都必须另外记为方法泛化缺口。

## 2. 冻结方法后，新环境需要提供什么

当前 Authorization DAG 的核心语言已经固定为五类节点、五类边和七个关系算子：

```text
节点：Source / Transform / Constraint / Effect / Delegation
边：data_dep / guards / binds / version_dep / delegates
算子：select / project / join / aggregate / compute / normalize / template
```

一个新 benchmark 的适配面可以分为四层。

### 2.1 工具 schema 接入

系统首先读取工具名称、描述、输入字段、必填字段和返回结构。字段枚举可以从 JSON Schema 自动完成；人工需要确认的是工具属于只读 observation、对外 observation，还是产生真实副作用的 Effect。

对 Effect 工具，契约最少包含：

```text
tool name
→ effect class
→ security-critical fields
→ required fields
```

这项成本应按“需要人工确认的工具数”计算，而不是按任务数计算。同一工具服务一百个任务，契约仍只声明一次。

### 2.2 Effect 语义与动态能力关系

若新工具可以映射到现有 Effect 类别，只增加一条工具契约，不修改 DSL。当前共享 Effect 语言包含26类用户可见后果，例如消息发送、文件修改、权限变更、资金转移、购买、仓库修改和凭据更新。

动态中间工具需要额外声明其与终端 Effect 的关系。例如 `create_dir` 可能是下载文件的必要前置步骤，`cart_add_product` 可能是结账的必要步骤。每条声明只描述稳定的工具依赖和需要保持一致的字段，不能包含任务 ID、攻击标签或从结果中归纳出的具体值。

### 2.3 执行事件接入

运行时至少要提供下列规范事件：

```text
trusted_user_message
tool_call(tool, arguments, call_id)
tool_result(call_id, value, success)
state_read(object, version)
state_change(object, before_version, after_version)
```

如果 benchmark 原生提供这些字段，只需字段重命名；如果工具调用、返回和状态变化分散在不同日志中，则需要一个 trace adapter 将它们恢复为时间有序事件。该成本取决于日志格式数和缺失事件种类，而不取决于 case 数量。

### 2.4 评测 oracle 接入

为了计算正常放行率和攻击阻断率，还需把 benchmark 标签映射到候选调用或持久状态变化。这属于实验基础设施，不进入线上防御模块，也不能被契约生成器读取。

## 3. 适配成本的量化模型

定义：

```text
T  = benchmark 中的工具总数
Te = 产生副作用的工具数
Ta = 无法仅凭 schema 自动确定角色或 Effect 的工具数
Ec = 复用现有 Effect 类别的副作用工具数
En = 需要新增 Effect 类别的工具数
Cr = 需要声明的动态能力关系数
Sa = 需要声明的等价来源组数
Op = 需要新增的 DSL 算子数
Ev = 需要新适配的事件格式或缺失事件种类数
Or = 只用于评测的 oracle 映射数
```

方法适配成本报告为一个向量，而不是混成单一 LOC：

```text
C_method = ⟨Ta, En, Cr, Sa, Op, Ev⟩
C_eval   = ⟨case-format adapters, Or, evaluation LOC⟩
```

为了比较不同 benchmark，可进一步报告五个比例：

```text
Schema 自动接入率       = 自动解析 schema 的工具数 / T
Effect 本体复用率       = Ec / Te
工具角色人工标注率     = Ta / T
DSL 表达覆盖率          = 无需新增算子的 Binding 类型数 / 全部 Binding 类型数
运行事件可观测率       = 可稳定取得的规范事件种类 / 5
```

其中 `En > 0` 表示现有 Effect 本体缺口，`Op > 0` 表示 DSL 表达能力缺口；这两项比普通工具契约更昂贵，因为它们会修改共享方法，而不是增加部署配置。若某项规则包含任务 ID、case 名称、攻击目标或测试后才知道的值，应直接记为 case-specific patch，不计入合法适配成本。

## 4. 当前三个 Benchmark 暴露出的适配规模

下表统计的是当前仓库中可明确识别的声明面，用于建立数量级；由于三套接入是在不同研发阶段形成的，不能把代码行数直接解释为公平的人力比较。

| Benchmark | 已观察工具 | Effect/契约声明 | 动态关系与来源别名 | 新增核心算子 |
|---|---:|---:|---:|---:|
| AgentDojo | 56 | 24条 Effect 规格 | 主要复用通用读取与参数溯源 | 0 |
| AgentDyn | 49 | 34个工具标记为 Effect | 13条能力关系；2类等价来源组 | 0 |
| GreatWallBench | 由工具 schema 自动枚举 | 17条工具到 Effect 映射，另加1个宿主持久状态 Effect | 当前未增加 task-specific 能力规则 | 0 |

三套 benchmark 均复用了相同的七个 DAG 算子，说明目前可见差异主要落在工具契约和动态能力关系，而不是 DSL 语法扩展。AgentDyn 的主要适配负担是开放动态路径：需要声明哪些中间工具可能服务于哪个终端 Effect。GreatWallBench 的主要额外负担是 OpenClaw 的多轮消息和工作区持久状态：工具 schema 本身可以自动解析，但需要把文件/记忆读写接入状态版本事件。

当前 GreatWallBench 目录包含305行数据适配器和105行契约生成代码，但前者还包含数据发现、标签隔离和攻击目标匹配，属于评测成本；后者才更接近方法部署成本。AgentDyn 的295行全量脚本同样混合了任务遍历、环境执行、指标统计和少量运行时适配。由此可见，直接比较总 LOC 会严重高估方法适配成本。

## 5. 如何判断方法具有泛用性

对下一个 benchmark，应在查看检测结果之前冻结适配产物，并记录：

1. 只根据工具 schema、官方工具文档和日志格式生成工具契约与 trace adapter；
2. 记录人工确认过的工具数、Effect 映射、能力关系、来源别名和事件映射；
3. 在首次运行前冻结 `C_method`，禁止读取攻击标签和 case 结果；
4. 首次全量运行后，将所有修改分为三类：契约事实纠错、共享方法缺口、case-specific patch；
5. 只允许前两类进入正式版本，并单独报告修改前后的结果；case-specific patch 不进入方法。

如果新 benchmark 满足以下条件，才能说明当前方法具有较低适配成本：大部分工具 schema 自动接入；Effect 本体复用率高；无需新增 DSL 算子；人工工作集中于少量工具角色和稳定能力关系；首次冻结版本已经具备可接受的正常放行与攻击阻断能力。反之，即使调试后指标很高，只要需要根据任务轨迹不断增加规则，也不能证明泛用性。

## 6. 下一步在实验前先完成的静态审计

在选择新 benchmark 后，先不运行任何攻击或正常任务，只完成一张适配清单：

```text
工具总数与 schema 完整度
→ 自动/人工工具角色分类
→ 现有 Effect 本体覆盖
→ 动态能力关系候选
→ 七个 DSL 算子的表达覆盖
→ 五类运行事件的可观测性
→ 评测 oracle 与防御输入的隔离方式
```

这张清单本身即可给出预测的 `C_method` 和 `C_eval`。随后真正运行实验时，重点不只是报告准确率，还要报告预测成本与实际追加成本的差距；该差距才是当前方法泛用性的直接证据。
