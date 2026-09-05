# GreatWallGuard

GreatWallGuard 是一个最小可运行的运行时防御原型，验证论文中的核心假设：

> 长程攻击的单步动作可能看起来合理，但攻击成功必须留下可被后续步骤利用的持久 Effect。防御系统不保存全部长上下文，而是把“观测 → 行为 → Effect → 状态变化”压缩成跨轮图，并在副作用提交前执行任务级授权。

## 原型做什么

1. 将用户输入、工具返回、文件 / 记忆读取等信息记录为带来源标签的观测节点。
2. 将 tool call 记录为行为节点，将工具调用映射为有限的 Effect 类型：`read`、`write`、`create`、`delete`、`send`、`execute`、`permission_change`、`unknown`。
3. 只有实际提交的持久 Effect 才生成状态版本节点；原始长文本只保存摘要和哈希，不进入跨轮状态。
4. 用 `TaskScope` 定义任务级最小权限。权限来自用户 / 系统授权，不从工具返回、文件或记忆内容中自动升级。
5. 在 tool call 执行前返回 `ALLOW`、`ASK` 或 `BLOCK`，并保留可审计的图。

它不是一个完整的恶意意图分类器，也不假设“所有外部数据都恶意”。语义模型可以作为 TaskScope 生成器或风险探针，但最终副作用的提交由结构化 Effect 和确定性策略控制。

## 最小流转

```text
用户输入 / 工具返回
          │
          ▼
    观测节点（来源、完整性、摘要）
          │
          ▼
    行为节点（工具、参数摘要）
          │  infer
          ▼
    Effect 节点（类型、目标、是否持久）
          │  commit only after authorization
          ▼
    状态版本（文件、记忆、配置、外部副作用）
          │
          └──── 下一轮读取 / 规划
```

## 运行验证

无需 API key：

```bash
python -m unittest discover -s tests -v
python examples/demo_longrange.py
```

预期行为：报告文件写入被允许；外部工具返回不能授予外发权限；后续 `send_email` 在任务范围外被阻断；图中保留跨轮的 `write → state` 传播链。

## 与现有 CFG / DFG / provenance 图的关系

现有图方法主要表示当前动作由什么来源、控制流或数据依赖驱动，并据此做局部异常或白名单检查。本原型不替代这些图，而是在其上增加一层跨轮的持久状态压缩：图的安全对象不是“某个来源天然恶意”，而是“某次行为实际改变了什么，以及该改变是否被当前任务授权”。

## 当前边界

- 工具语义通过显式 `ToolContractRegistry` 提供；未知工具默认产生 `unknown` Effect 并进入 `ASK`。
- 目标匹配使用前缀和显式目的地策略，尚未接入白盒 hidden-state probe 或 LLM 意图模型。
- 该仓库只在沙箱和离线 trace 上验证防御逻辑，不连接真实生产系统。

