---
name: dz-transcript-search
description: "Use when needing to fuzzy search or semantically retrieve coding agent logs and conversation transcripts across a flexible time window (e.g. today, past 3 days, specific date ranges). Triggers on: '搜日志', '查历史会话', '模糊搜索日志', '搜历史记录', '查一下关于xxx的会话', '/dz-transcript-search'."
---

# 多智能体会话日志模糊与语义检索技能 (Transcript Search)

## 概述
跨机器上全量编码智能体（Antigravity、OMP、Claude Code、Codex、Pi、Cursor 等 20+ 款）的异构日志存储，**在任意自定义时间范围内（今天、昨天、近N天、指定日期区间）执行高性能的模糊与语义检索**。

基于**灵活时空过滤 + 内存 SQLite FTS5 倒排索引 + 纯本地轻量混合语义评分**，实现**零常驻守护进程（Zero-Daemon）、零外部向量 API 依赖（Zero-API）、秒级即用即走**。以项目为纲，分级输出 Markdown 原生嵌套缩进看板，高亮命中切片并提供原生恢复命令。

## 适用场景
- **记忆模糊定位**：询问“前几天我跟 Claude 讨论过支付回调签名在哪”、“上周关于状态机重构的会话”。
- **跨时段回溯检索**：突破 `workday-recall` 仅限昨日断点的限制，支持查询近 3 天、近 7 天、近 30 天或特定日期的工作足迹。
- **排查具体代码/命令**：通过 `--deep` 模式穿透到底层 `transcript.jsonl`，查找某个具体的 `git` 命令、工具调用参数或异常堆栈。

> [!IMPORTANT]
> **单步即刻交付契约（Zero-Drift Policy）**：
> 本技能为纯粹的会话日志检索引擎。运行 `search_agent_logs.py` 获取看板输出后，**必须立即、原样将看板输出给用户并彻底终止当前工具链调用（零多余步骤）**。
> **绝对严禁**在拿到检索结果后自作主张继续调用 bash、grep、read_file 去深挖代码实现、调研业务逻辑或写分析长文。一切后续动作交由用户看后在下一轮发起。

---

## 执行协议 (Execution Protocol)

### 步骤 1：调用内置检索脚本
在终端或工作区中，直接运行本技能内置的高性能检索引擎：

```bash
# 1. 自然语言语义检索（主要用法：像描述记忆一样直接问，默认近 7 天）
python3 <skill-dir>/scripts/search_agent_logs.py "前几天跟 Claude 讨论过支付回调签名在哪"
#    同样兼容关键词或短语
python3 <skill-dir>/scripts/search_agent_logs.py "支付回调 状态机"

# 2. 指定相对时间窗口（如近 3 天、昨天、今天）
python3 <skill-dir>/scripts/search_agent_logs.py "<搜索词>" --since 3d

# 3. 指定绝对日期范围
python3 <skill-dir>/scripts/search_agent_logs.py "<搜索词>" --since 2026-10-15 --until 2026-10-22

# 4. 深度穿透模式（扫描底层工具调用命令与执行详情）
python3 <skill-dir>/scripts/search_agent_logs.py "<搜索词>" --deep

# 5. 限定特定智能体与工作区
python3 <skill-dir>/scripts/search_agent_logs.py "<搜索词>" --agent antigravity --project /path/to/project

# 6. 紧凑/Token 友好模式（极简单行输出，适合 Agent 管道调用）
python3 <skill-dir>/scripts/search_agent_logs.py "<搜索词>" --compact
```

### 步骤 2：参数说明
- `query`：搜索关键词或短语（支持多词空格拆分与自然语言）。
- `--since`：起始时间，支持 `today`、`yesterday`、`3d`、`7d`、`30d`、`YYYY-MM-DD`（默认 `7d`）。
- `--until`：截止时间，支持 `now`、`yesterday`、`YYYY-MM-DD`（默认当前时间）。
- `--compact`：启用紧凑/Token 友好模式，单行输出极简概要与恢复命令。
- `--deep`：开启底层消息流与工具调用深度穿透扫描。
- `--project`：限定特定项目/工作区物理路径。
- `--agent`：限定智能体名称（如 `antigravity`, `claude`, `codex`, `omp`, `pi` 等）。
- `--total-elapsed`：可选，外部透传的交互总时延（秒），用于准确呈现端到端全链路耗时。
- `--json`：以 JSON 格式输出原始结构化数据。

---

## 输出契约 (Output Contract)

严格遵循原生嵌套列表与 `/bro` 讲人话契约输出：

```markdown
### 🔍 会话日志模糊与语义检索看板
`[⚡ 引擎耗时: 0.XXs]`  `[🕒 检索跨度: <SPAN>]`  `[📊 命中: X 会话]`
> 🎯 检索词: `<QUERY>` | 🕒 窗口明细: <START_TIME> ~ <END_TIME> (<SPAN_DETAIL>)

📁 【项目名】 (`<WORKSPACE_PATH>`) ★当前仓库
- 项目路径: `<WORKSPACE_PATH>`
- 🤖 **[AGENT_NAME]** (命中 X 条会话):
  - 🌟 [语义相关度 XX%] (<TIMESTAMP>): <会话主题> ➔ <核心交付产出与结论>
    - ⚡ 恢复命令: `<RESUME_COMMAND>`
    - 🔍 命中切片: > "...上下文内容 [MATCH]匹配词[/MATCH] 关键信息..."
    - 📂 日志路径: [transcript.jsonl](file://<TRANSCRIPT_PATH>)

──────────────────────────────────────────────────────────────────────

📁 【其他项目名】 (`<OTHER_PATH>`)
- 🤖 **[AGENT_NAME]** (命中 X 条会话):
  - 🔹 [相关度 XX%] (<TIMESTAMP>): <会话主题> ➔ <结论>
```

---

## 核心规则与注意事项
1. **即用即走，零后台开销**：平时绝不常驻任何后台守护进程与端口监听，完全依靠 Python 内存表与本地计算，秒级启动退出。
2. **纯本地离线计算**：严禁向外网调用任何需要 API Key 或付费的外部向量服务；若无本地向量库，纯靠内置数学相似度算法优雅降级。
3. **敏感信息自动脱敏**：命中上下文中的 API Key、Token、私钥和密码由提取器自动过滤为 `***SENSITIVE***`。
4. **原生多级缩进**：属性与子智能体使用 1 级列表（`- `），任务轨道使用 2 级列表（`  - `），命中切片与文件链接使用 3 级列表（`    - `），确保在所有富文本界面中视觉缩进清晰。
5. **保持指标卡完整真实**：输出看板时，顶部必须完整保留 `[⚡ 引擎耗时: X.XXs]`（或透传的 `[⚡ 交互时延: X.Xs (引擎: X.XXs)]`）、`[🕒 检索跨度: ...]` 和 `[📊 命中: ...]` 三大指标徽章，严禁裁切耗时数据。
6. **严禁全盘扫描与临时脚本盲试**：底层已内置 7d ➔ 30d 受控自适应阶梯扩围机制，未显式指定时间且初次未命中时会自动级联；智能体严禁执行 `find / -name ...` 或手写 Python 脚本探查日志目录。
7. **拿到结果立即结束响应**：检索是单一任务闭环，严禁在一次检索中捆绑执行后续业务代码探索或方案调研。
