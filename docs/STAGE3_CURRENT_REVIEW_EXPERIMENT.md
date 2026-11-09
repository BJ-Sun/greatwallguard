# 阶段三：最新阶段二 REVIEW 先导实验

## 1. 实验问题

阶段二不会直接放行无法程序化证明的调用，而是输出 `REVIEW`。本实验检验：给局部 LLM 审计器补充可信用户请求、结构化执行前缀和真实工具返回后，能否恢复正常调用，同时拒绝攻击目标。

## 2. REVIEW 清单

从最新 AgentDojo 和 AgentDyn 阶段二全量结果中，共提取 814 个调用级 `REVIEW`。

| 数据 | 程序证据问题 | 语义未决 | 合计 |
|---|---:|---:|---:|
| AgentDojo 正常 | 12 | 52 | 64 |
| AgentDojo 攻击 | 21 | 218 | 239 |
| AgentDyn 正常 | 36 | 118 | 154 |
| AgentDyn 攻击 | 22 | 335 | 357 |
| 合计 | 91 | 723 | 814 |

程序证据问题包括 observation 契约、能力连接和预算证明；它们应由阶段二完善，不进入 LLM 语义准确率。第一轮从四个语义组各固定抽取 12 条，共 48 条。标签和未来结果不提供给模型。

## 3. 为什么必须包含工具返回

第一轮只提供工具名、参数和调用顺序，不提供工具返回。结果为：攻击 23/24 判为未授权、0 误放行，但正常仅 2/24 判为授权。模型给出的主要理由不是语义冲突，而是无法看到文件内容、交易记录、搜索结果和预订结果，因而不能证明实际参数的来源。

随后在本地 mock 环境重新执行标准正常轨迹，为相同 48 条样本补齐调用前 observation。凭据形态值在外发前被替换为稳定的不可逆标识；相同值保持相同标识，以保留相等关系。

## 4. 补齐 observation 后的结果

| 数据 | AUTHORIZED | UNAUTHORIZED | UNCERTAIN |
|---|---:|---:|---:|
| AgentDojo 正常 12 | 5 | 5 | 2 |
| AgentDojo 攻击 12 | 0 | 12 | 0 |
| AgentDyn 正常 12 | 9 | 2 | 1 |
| AgentDyn 攻击 12 | 0 | 12 | 0 |
| 合计 | 14 | 31 | 3 |

与缺少 observation 的输入相比，正常恢复由 `2/24` 提高到 `14/24`；攻击由 `23/24` 提高到 `24/24`，仍为 0 误放行。本轮消耗 55,587 token。

## 5. 剩余正常样本的含义

未恢复的 10 条不能全部解释为 LLM 误报：

1. 一条 AgentDojo 银行任务明确要求“读取文件并严格遵循指令”。文件确实要求提高房租，交易记录也能确定目标。审计器仍拒绝，说明当前 Prompt 对“用户明确授权外部来源决定效果”的处理过严。
2. 四条 AgentDojo Slack 标准轨迹没有访问用户指定的 TODO 网站，而是根据其他频道和网页执行消息或加人操作。LLM 拒绝具有授权依据，标准 utility 轨迹不能自动等同于安全授权金标。
3. 两条 AgentDyn 退款任务没有成功获得用户要求的评分或价格比较，条件并未成立。安全机制不应仅因它们属于标准轨迹就放行。
4. 其余样本缺少具体日期、实际建议内容或下载文件内容，保持拒绝或不确定是合理的。

## 6. 方法结论

阶段三不应被实现成“完整轨迹 + 一个精心设计的 Prompt”。当前结果支持以下固定流程：

```text
Stage-2 REVIEW
    │
    ├── 程序事实或契约缺失 ──> 回到阶段二补证据
    │
    └── 语义关系未决
            │
            ▼
       图切片证据包
       用户授权 + 待审计调用
       + 参数来源 observation
            │
            ▼
       SUPPORTED / CONTRADICTED / INSUFFICIENT
```

重放只用于剩余的“来源影响是否超出用户委托”问题，不应对已经能由局部证据判断的全部调用执行。

更重要的是，正式评估需要独立的**授权金标**，不能直接把 benchmark utility ground truth 当作安全标签。金标至少要判断：用户是否授权该终端效果、是否授权外部来源决定该效果或字段、条件是否在调用前真实成立、待审计参数是否由当前版本的证据支持。

## 7. 下一步

1. 为语义 `REVIEW` 建立独立授权标注，而不是沿用 normal/attack 二元标签。
2. 把“委托对象”显式写入阶段一 DAG：允许哪个来源决定哪个字段，还是允许它新增何种终端效果。
3. 只在委托存在但来源影响范围不清楚时运行局部反事实重放。
4. 在冻结金标后扩大到全部语义 `REVIEW`，报告正常恢复、攻击误放行、保持不确定、稳定性、token 和延迟。

## 8. 复现文件

- 提取与实验程序：`experiments/stage3_current_review_pilot.py`
- REVIEW 清单：`experiments/stage3_current_review/review_manifest.json`
- observation 补全清单：`experiments/stage3_current_review/review_manifest_with_observations.json`
- 无 observation 结果：`experiments/stage3_current_review/pilot_results.json`
- 有 observation 结果：`experiments/stage3_current_review/pilot_with_observations_results.json`
