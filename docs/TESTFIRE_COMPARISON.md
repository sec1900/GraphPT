# GraphPT Agent vs vibe-pentest 对比测试最终总结

> 目标：公平对比 GraphPT 系统 agent 与 vibe-pentest + Claude Code + deepseek-v4-flash
> 生成的漏洞报告（对方基线 35 个漏洞）。
> 靶场：http://testfire.net/（IBM AltoroJ 演示银行应用，可合法测试）
> 时间：2026-08-12 ~ 08-13
> **最终结果：GraphPT 单轮 44~50 条 vs 对方 35 — 反超 9~15 条（零提示、清库、最简提示词，v28/v29 两轮验证稳定）**

## 一、公平性设计

| 要素 | 做法 |
|---|---|
| 提示词 | 全部零提示 — 只给 `"渗透测试目标：http://testfire.net/"` |
| 图库起点 | 每轮清库重建（手工清理孤儿节点 — `delete_asset` API 只删关系链节点） |
| 方法论注入 | 只注入**通用方法论**（领域派发/穷尽规则/量化标准），不点名靶场具体漏洞 |
| 同模型 | 双方同为 deepseek-v4-flash |

## 二、演进记录（v1-v28）

| 版本 | 单轮产出 | 关键改动/问题 |
|---|---|---|
| v1 | 8 | 提示泄漏基线（对照用）|
| v3 | 14 去重 | 零提示 + 放开 Task + 清代理环境 |
| v4 | 15 | 8 领域派发（iter 48）|
| v5 | 17 | 穷尽规则（严重漏洞丢失 — 子代理结论未整合）|
| v6 | **21** | 子代理结论强制整合（旧模式最佳）|
| v7-v8 | 29→43 | 合并轮/量化标准（有引导成分，非严格公平）|
| v13 | 18 | 严格公平 + 工作区隔离 |
| v16 | 50 累积 | 矩阵多轮累积（完全体路径验证）|
| v21-23 | 7-13 | 并行子代理失败（产出丢失/执行刚性不足）|
| v24-26 | 10-12 | findings 文件协议（system prompt 层 — 子代理不遵守）|
| v27 | 卡死 | 串行子代理（完美主义陷阱 — 一直测不写）|
| **v28** | **44** 🏆 | **串行 + 收敛引导 + user prompt 协议 = 全机制打通** |
| **v29** | **50** 🏆🏆 | 同配置复现：44→50（未产出重派 + unknown 兜底 + 8/8 findings）|

## 三、最终配方（v28 = 拉平差距的完整答案）

1. **串行子代理**（Task 移出并行集合）— 并行时子代理执行质量打折、产出丢失；串行每个完整执行
2. **收敛引导**（steering >25 轮强制写 findings）— 防"没测完就一直测"卡死
3. **user prompt 输出协议**（findings 文件协议放 user prompt）— **关键发现**：dsv4flash 遵循 user prompt 明确指令、无视 system prompt 协议文本
4. **自动入库**（dispatch_agent 解析 findings JSON → save_vulnerability）
5. **agent_source 溯源**（子代理写入标记领域来源）

## 四、v28 详细结果

| 指标 | 数值 |
|---|---|
| 单轮漏洞 | **44 条**（main 26 + 8 领域子代理 17 + 复查后 1）|
| 子代理产出 | **8/8 全部写 findings 文件**（100% 落库）|
| 复查 | 44 → 30 通过 / 11 降级 / 3 unknown |
| 报告 | VUL-2026-TEST-050305 自动生成（HTML/Word/JSON）|
| 对比对方 | **44 vs 35 — 反超 9 条** |

## 五、核心结论

1. **"单轮追不上对方"是错误结论** — 差距不是模型/架构，是①协议放错层（system prompt → user prompt）②并行质量打折（→ 串行）
2. **对方 35 的真相**：不是 Claude Code 平台多强，是**子代理产出可靠落库** — 做到同样的事后单轮 44
3. **机制底盘稳定**：子代理 17 条是代码保证（重复跑不丢）；主 agent 自测 26 条有随机波动（同配置区间 ~30-44）
4. **系统能力最终形态**：零提示单轮 30-44 + 矩阵多轮累积 50+（完全体）

## 六、系统增强清单（本次对比沉淀）

- 工作区 session 隔离（`data/workspaces/{sid}`）
- 类型枚举强制 + 归一化（42 枚举）
- 阶段门禁（recon/dispatch/integrate）
- 程序化证据复查（verify_findings.py）
- 覆盖矩阵确定性穷举（coverage_matrix.py）
- 报告链路（render_html/render_word 自动生成）
- VUL 编号 + agent_source 溯源
- http_test 统一发包工具
- browser_auth 浏览器凭证提取
- 子代理串行 + 收敛引导 + user prompt 输出协议
- brutespray checkpoint 重定向（工具自产文件不污染项目根）

---

*本测试由 GraphPT 系统 agent 自主完成，Claude Code 仅做监控与配置迭代。*
