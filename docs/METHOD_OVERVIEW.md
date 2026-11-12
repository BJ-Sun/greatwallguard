# GreatWallGuard 方法概览：Progressive Authorization Proof

正常 Agent 的工具路径和参数具有动态性，无法在执行前穷举；但如果把动态规划完全交给 Agent，攻击者又可以借外部网页、邮件、文件或记忆影响规划，新增工具、替换参数并扩大最终效果。例如，用户只要求购买一台相机，正常 Agent 可能动态搜索商品、查看详情、加入购物车并结算；恶意网页也可能诱导它额外发送用户信息。固定工具序列会误拦前者，完全开放工具选择则会放过后者。因此，我们要解决的不是“Agent 是否偏离某条预生成计划”，而是“动态产生的行为是否仍能由用户授权解释”。

长程攻击可以把目标拆成多个局部合理的步骤，但要跨步累积并最终造成可观察危害，至少一个步骤必须产生可被后续利用或直接改变环境的 **Effect**。Effect 包括发送消息、转账或购买、删除或发布资源、修改文件与配置、写入记忆、改变权限和凭据，以及创建可在后续触发的任务。由此，防御问题可以转化为：在 Effect 即将发生或被后续状态使用时，识别用户授权行为与被误导 Agent 行为之间的差异。该差异由简到难依次表现为：新增终端 Effect；工具路径不同但可能是正常动态执行；同一工具下固定参数错误；动态参数的来源或计算过程错误；以及工具、来源和数据流均相似、只有任务语义不同。仍以购物任务为例，额外发送邮件属于新增 Effect，`add_to_cart` 可能只是正常中间工具，购买数量错误属于固定参数冲突，购买的商品不是搜索结果中评分最高者属于动态 Binding 冲突，而“最适合出差的相机”是否对应某个候选商品则属于语义未决关系。

我们的目标是在不固定唯一执行路径的情况下，为每个真实 Effect 建立一条从可信用户请求到实际工具调用的授权证明。关键观察是：无论执行过程如何动态变化，外部内容都不能自行新增终端 Effect、扩大被操作的对象和数据范围，或绕过用户规定的条件与预算。基于这一边界，我们提出 **Progressive Authorization Proof**：差异越明显，越优先使用便宜、确定且可复核的程序证明；只有当 Effect、工具能力、参数来源和计算过程均无法形成明确结论时，才把剩余的一条局部语义关系升级给 LLM。系统因此不是为不同攻击分别增加检测规则，而是按照授权关系的可判定程度，从结构、关系逐步深入到语义。

Progressive Authorization Proof 由三个前后衔接的子方法组成。**Authorization Compilation** 将可信用户请求编译为路径无关的 Authorization DAG，规定允许的终端 Effect、关键参数的形成关系、委托、条件和预算，相当于生成“证明标准”。**Deterministic Runtime Proof** 在工具网关记录实际调用与返回，依次检查终端 Effect、动态读取与中间能力、固定参数和动态 Binding，相当于使用程序证据“执行证明”。**Semantic Proof Completion** 只处理程序证明留下的局部断点：系统将其转化为原子 Proof Obligation，切取最小证据，再让 LLM 给出 `SUPPORTED / CONTRADICTED / NEED_EVIDENCE` 三态结论，并由程序验证冲突、补充事实或请求用户确认，相当于“补全证明缺口”。三个子方法不是三个独立检测器，而是定义证明目标、完成确定性证明和补全剩余语义的同一条流水线。

完整流程可以用购物案例串联。用户要求“从指定目录中购买价格低于 500 元且评分最高的相机”，阶段一生成 `search_products → select(price<500) → argmax(rating) → project(product_id) → checkout` 的授权关系，但不固定商品 ID 和中间工具顺序。运行时若 Agent 调用 `send_email`，阶段二在 Effect 层直接拒绝；若调用 `add_to_cart(P17)`，系统根据工具能力契约和对象连接判断它是否为 `checkout(P17)` 的正常中间步骤；若调用 `checkout(P99)`，系统用真实搜索结果执行 DAG，比较授权计算结果与实际参数；若用户改为“购买最适合出差的相机”，有限算子无法判断 P17 是否满足该语义，阶段三只审计“P17 是否符合最适合出差”这一原子关系。最终，明显偏离被低成本阻断，正常动态路径由关系证明容忍，真正难以程序化的语义才进入受约束审计。

```text
可信用户请求 + 工具／效果契约
              │
              ▼
① Authorization Compilation
   自然语言 → Authorization DAG
   生成证明标准
              │
              ▼
② Deterministic Runtime Proof
   Effect → 动态工具 → 固定参数 → 动态 Binding
   完成结构与关系证明
              │
        ┌─────┼─────┐
      ALLOW  REVIEW  ALERT
              │
              ▼
③ Semantic Proof Completion
   原子问题 → 最小证据 → 三态语义证明
              │
              ▼
       ALLOW / DENY / CONFIRM
```

详细设计分别见：[阶段一：授权编译](STAGE1_AUTHORIZATION_COMPILATION_DETAILS.md)、[阶段二：运行时授权证明](STAGE2_RUNTIME_AUTHORIZATION_PROOF_DETAILS.md)和[阶段三：语义证明补全](STAGE3_SEMANTIC_PROOF_COMPLETION_DETAILS.md)。
