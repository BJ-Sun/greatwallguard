# 逐轮授权时间线

长程任务中的授权不是整段对话的无序并集。后续消息只能影响其后的行为，不能追认此前的调用；用户重新指定同一行为时，新参数和预算也不能与旧版本混用。因此，在线系统按真实到达顺序维护授权：

```text
可信用户消息 u_t
    → 独立编译并校验 DAG Δ_t
    → 为本轮节点分配独立命名空间
    → 替换同一工具的旧授权，或显式撤销指定授权
    → 更新当前 Authorization DAG A_t
    → 审查随后发生的工具调用与状态写入
```

形式上，当前授权为 `A_t = Update(A_{t-1}, Δ_t)`。`Δ_t` 只能来自本轮可信用户消息和部署工具契约。系统不会重新解释旧工具返回来生成授权，也不会让 `Δ_t` 作用于时间上早于它的调用。

## 更新语义

公共模块支持五种更新：

- **ADD：**加入新的工具或 Effect 授权；
- **REFINE：**只补全原本未确定的参数或条件；若改变已有确定值，程序自动规范化为 `REPLACE`；
- **REPLACE：**撤销被替代的旧授权，再加入具有独立参数关系和预算的新授权；
- **REVOKE：**立即停用明确指定的授权节点；
- **CONTEXT_ONLY：**记录本轮上下文，不扩大可执行权限。

同一工具默认采用保守的“最新授权替代旧授权”。这避免“改发给 Bob”之后 Alice 的旧授权继续有效，也使“再执行一次”获得新的独立预算。需要同时保留多个并行授权时，调用方可关闭自动替换，并显式管理各 Effect ID。

## 与状态版本的关系

文件、记忆和配置的每次真实变化都形成不可变版本：

```text
object_id + parent_version + new_version
          + created_by_call
          + write_authorized_at_t
```

其中 `write_authorized_at_t` 使用写入发生时的 `A_t` 判定，而不是会话结束后的最终授权。后续读取某版本并生成工具参数时，运行时沿版本链检查是否包含明确未授权写入；存在未授权写入则 `ALERT`，授权证据未知则 `REVIEW`。

## 当前实现与边界

公共入口为 `GreatWallGuardMethod.start_session()`；每次用户消息调用 `session.apply_user_turn(turn, message)`，工具调用仍由 `session.runtime.authorize_tool_call(...)` 审查。底层实现位于：

- `authorization_timeline.py`：DAG 增量合并、命名空间、替换与撤销；
- `persistent_state.py`：文件/记忆版本及写入时授权记录；
- `intent_dag_compiler.py`：无法闭合的编译关系降级为 REVIEW 型节点。

`authorization_update_compiler.py` 从本轮可信用户消息提出上述更新操作，程序随后校验目标 Effect ID、工具契约、字段和嵌套 Authorization IR。模型不能直接修改运行时权限；只有校验通过的更新才能进入时间线。语义不明确的延续消息被记录为 `CONTEXT_ONLY` 并标记待审查。

## 验证结果

更新操作 pilot 使用 18 段对话、34 轮消息；经程序规范化后，34/34 轮与研究者预先定义的更新类型一致，未观察到错误扩权或错误撤权。GreatWallBench 全量回放覆盖 240 条正常任务和 405 条严格双成功攻击，645 条均成功运行：正常任务为 163 `ALLOW`、69 `REVIEW`、8 `ALERT`；攻击目标为 351 `ALERT`、54 `REVIEW`、0 `ALLOW`。逐 case 分析见 [GreatWallBench 阶段一、二结果](GREATWALLBENCH_STAGE12_RESULTS.md)。
