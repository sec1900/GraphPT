# 治理账本 · 2026-08-31 大学渗透观测 → 全量修复

> 数据来源：8/30 晚 ~ 8/31 早对某大学（gzky.edu.cn / jwgl.gzky.edu.cn）真实渗透观测——
> sqlite findings / traffic.db / tmp URL 清单 / relay 会话日志 / 工具 cache / 图库快照。
> 每一项均有数据实锤，治理方式为代码+数据双落地。回归：`pytest tests/` 61 passed。

---

## 观测全景（数字）

| 指标 | 数值 | 结论 |
|---|---|---|
| 整夜 findings | 1,568 | 99.6% 是泛解析垃圾 |
| wildcard DNS 垃圾发现 | 1,500（785 独立随机域） | nuclei 模板被泛解析打爆 |
| 扫描 URL 列表 | 33,698 行/批，~82% 垃圾 | 全链被稀释 |
| httpx 请求 | 1,853（大量重复） | 同一 4 目标 2-3 分钟重复探测 |
| relay agent 接力 | 7 轮 / 425 迭代 / 10.6M tokens / **0 提交** | 无界空转 |
| 可用发现 | 6 条（弱配置类 info） | 信噪比 ~0.4% |

---

## 治理项（15 项全部落地）

### A. 资产测绘污染链（P0）

| # | 问题 | 修复 | 文件 |
|---|---|---|---|
| A1 | 泛解析探测名（3ie…-3ie…）当真实资产写入图；wildcard_ips 只存不用 | `write_domain` 域名质量门：探测名签名 `^[a-z0-9]{14,}(-[a-z0-9]{14,})+$`、>32 位随机 label 拒收（返回 rejected 兼容调用方）；`write_ip` 命中资产 wildcard_ips 打 `is_wildcard_probe` 标记 | `common/asset_identity.py` `collector/neo4j_client.py` |
| A2 | nuclei `wildcard-dns-detect` 对每个随机子域各出一发现 | adapter 特判：按可注册根域折叠为 1 条 `wildcard_result`（资产属性），不再产生 vulnerability finding | `tools/nuclei/adapter.py` |
| A3 | `scan:default` 与 `scan:gzky` 各写一份（783/785 双写）；指纹含随机域去重失效 | findings 去重查询去 `task_id` 过滤（跨任务全局去重）；指纹 target 折叠探测名到根域 | `core/finding_pool.py` |
| B | 双扫描线并行消费同一根域（整链 ×2） | 根域级 Redis 互斥锁（`scheduler:root-line:<root>`）：先到者持锁+心跳续期，后到者返回 locked；`http 已修复` | `collector/scheduler.py` |
| C | 存量 1,548 垃圾行 / 1,495 条垃圾流量 / 27,764 行垃圾 URL | `scripts/gov_cleanup_junk.py`：先备份（`data/backups/*_gov_cleanup_*.db`）后删；findings 1569→14；`enscan.gob` 入 .gitignore | `scripts/gov_cleanup_junk.py` |

### B. 探测节流与工程健壮性（P1）

| # | 问题 | 修复 | 文件 |
|---|---|---|---|
| D | 同一批端点 2-3 分钟 / 2 小时重复探测 | URL 列表归一化去重（normalize_url + set）；`cooldown_hours` 参数注入（tool.yaml 配 24h，403bypass/api_prescan/browser_probe 三工具启用；默认 0 行为不变） | `collector/pipeline.py` `collector/scheduler.py` + 3 个 tool.yaml/targets.yaml |
| E | 工具层 4 类失败反复白跑 | 403bypass `--waf` nargs；python argv 合法性防御（MZ 实锤）；browser_probe 内核缺失快速失败（exit 2） | `tools/403bypass/403bypass.py` `tools/browser_probe/browser_probe.py` `collector/pipeline.py` |
| F | 403 边界无标记无视角 | HTTPEndpoint 写库打 `likely_waf`（403 创建，只升不降） | `collector/neo4j_client.py` |

### C. Agent 空转（P2）

| # | 问题 | 修复 | 文件 |
|---|---|---|---|
| G | 指纹识别到了（VSB9/金智/CAS）不落资产、不挂攻击面 | 指纹档案 `fingerprint_profiles.py`（VSB9/金智/正方/强智/CAS 公开攻击面映射）；扫描收尾聚合写回 `Asset.fingerprints/fingerprint_profiles` | `common/fingerprint_profiles.py` `collector/scheduler.py` |
| H | relay 无界接力（10.6M tokens / 0 提交） | `max_tokens` 预算（默认 1.2M/域）记账停机；干跑判据收紧（零工具调用轮=干跑）；`stopped_by` 原因字段 | `search/relay_runner.py` |
| I | 思维空转（1.5-2.1M token ↔ 35 次工具调用） | steering 注入"行动先行"信号（≥12 迭代且工具输出 <40% 时） | `search/agent_session.py` |
| J | vsb9_scan `--noproxy` 直连全 0 状态 + 把网络错误当 SQLi 证据；nuclei 版本不兼容 | 会话首帧注入环境事实：代理语义（经代理是常态，直连不可达是常态）、nuclei 版本（600s 缓存）、资产指纹档案 | `search/agent_session.py` |
| K | xss_test1→6 八分钟六版脚本堆积 | run_script 落盘前相似度查重（≥85% difflib 提示复用，不阻断） | `tools/defs.py` |
| L | 41 条零价值 facts（base64.js 存在/会话总结锚点） | board 事实质量门：拒绝 conclude-anchor、会话统计、无 grounding 空洞断言；只放行资产属性型/假设型 | `search/board.py` |
| M | submitted=0 无一次提交尝试 | 提交前 dry-run：`_flag_passes_dryrun`（格式 + body 非空），不符不占 wrong 配额并留痕 | `search/run_task.py` |

---

## 治理后预期指标

| 指标 | 治理前 | 治理后 |
|---|---|---|
| wildcard 垃圾 findings | 1,500 | ≤ 1/根域（资产属性化） |
| 扫描 URL 垃圾占比 | ~82% | ~0%（生成即过滤+归一） |
| 同一批端点 2h 内重复探测 | 3+ 次 | ≤1 次 |
| relay token/域 | 3.9M~6.8M | ≤1.2M 硬停 |
| board 零价值事实占比 | ~100% | 0 |
| 提交格式垃圾 | 无校验 | dry-run 拦截+留痕 |

## 运行时注意

- 清理备份在 `data/backups/graphpt_gov_cleanup_20260831_182748.db` / `traffic_gov_cleanup_20260831_182748.db`
- 本地 Neo4j 已由 `tools/neo4j/bin/neo4j.bat start` 拉起（服务形式启动需要管理员权限）
- `.pytest_tmp` 为测试临时目录（pytest.ini `--basetemp` 规避沙箱对系统 Temp 的权限拒绝）