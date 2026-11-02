# llm-authenticity-probe

判断一个 LLM API 端点背后**是不是它声称的那个模型**——专治中转站套壳、跨家族替换、协议层掺水。

只做两件事：

- **A 轴**：后端厂商指纹（`model` 回显、响应 ID 前缀、thinking 签名、beta 头校验…）
- **B 轴**：是否被注入内容审查层

两轴独立，不合并成一个分数——「真模型 + 注入审查」和「假模型 + 无审查」都是真实存在的组合。

> **方法论声明**：本工具**只能证伪，不能证实**。A 轴全通过只写「未见证伪性偏差」，
> 不写「确认是真 Claude」。高保真套壳同样能通过全部协议探针。

## 支持范围

| 模型家族 | 支持 |
|---|---|
| Claude 系（anthropic 协议） | ✅ |
| GPT 系（openai chat/completions 协议） | ✅ |
| gemini / glm / deepseek / qwen 等 | ❌ 直接返回「测不了」 |

## 用自然语言测试

这个技能是给 AI Agent 用的。你不需要记命令，直接说人话：

| 你说 | Agent 实际执行 | 行为 |
|---|---|---|
| 「测一下 claude-haiku-5-5」 | `--model claude-haiku-5-5` | 自动扫本机配置，找出所有同名端点并逐个探测 |
| 「我现在的模型是真的吗」 | `--current` | 自动选源：omp 与 WorkBuddy 最近使用记录，或 Claude Code、opencode、Codex 配置 |
| 「测一下这个端点」+ URL/Key | `--url ... --model ...` | 手动指定单个端点 |
| 「我机器上都有哪些模型」 | `--list-config` | 只读列出，不发请求 |
| 「把这些端点都测一遍」 | `--menu` / `--scan-config` | 勾选或批量扫描 |

**示例对话**

```
你：  测一下 claude-haiku-5-5
Agent：模型 claude-haiku-5-5 在 3 个端点可用：
         · relay-a  http://127.0.0.1:9999/v1/chat/completions
         · ...
       [逐个探测后]
       结论：未见跨家族替换 —— 回显与声称同属 anthropic 家族。
       人话：✅ 未发现掺水证据，模型可正常使用
```

```
你：  我现在的模型用的是哪个端点？
Agent：当前模型（最近使用）  my-relay/some-model
       定位端点  relay-a  http://127.0.0.1:9999/v1/chat/completions
```

Agent 会先读 `SKILL.md` 的判定规则，再按上表选择命令；若模型不属于
Claude/GPT 系，会直接回答「测不了」而不是硬跑。

## 快速开始

纯标准库，无第三方依赖（跑测试需要 pytest）：

```bash
# 1. 只给模型名：自动扫描本机 code agent 配置里的同名端点
python3 scripts/probe.py --model claude-haiku-5-5

# 2. 指定端点（凭据走环境变量，不进 argv）
export PROBE_KEY='sk-...'
python3 scripts/probe.py --url https://your-endpoint --model claude-opus-5-5

# 3. 列出 / 勾选 / 批量
python3 scripts/probe.py --list-config
python3 scripts/probe.py --menu
```

无参数运行即打印完整用法：

```bash
python3 scripts/probe.py
```

## 端点自动发现

`--list-config` / `--menu` / `--model` 会扫描本机六类配置：

| 来源 | 文件 |
|---|---|
| opencode | `~/.config/opencode/opencode.json` |
| omp | `~/.omp/agent/models.db` |
| Claude Code | `~/.claude/settings.json` |
| Codex | `~/.codex/config.toml` |
| WorkBuddy 国内版 | `~/.workbuddy/models.json` |
| WorkBuddy 国际版 | `~/.workbuddy-ai/models.json` |

默认只列「有凭据 + 协议兼容」的端点，`--all` 查看全量。符号链接、环境变量名映射均有处理。

## 凭据安全

- key 只走环境变量或配置文件，**绝不进 argv**（`ps` 不可见）
- 报告落盘权限 `0600`，响应摘录两层脱敏
- 发凭据前打印目标 origin 与 TLS 状态
- 公网 `http://` 默认拒绝；本地/内网允许并标注

## 能力边界

| 做不到 | 说明 |
|---|---|
| 证明「后端是官方算力」 | 只能证伪 |
| 检测同家族降级（opus→haiku） | 协议层无差异；交由外部能力基线工具裁定 |
| 观测「当前会话」的连接 | 探针只能发独立 HTTP 请求 |

判定为「真假无法确定」时，会自动委派外部能力基线工具（需自行安装，`--install-tools`）。

## 文档

- 完整判据、探针表与执行契约：[`SKILL.md`](SKILL.md)
- 社区采信基线锚点：[`docs/官方基线-社区采信.md`](docs/官方基线-社区采信.md)

## 测试

```bash
python3 -m pytest tests/ -q
```

## 免责声明

- **仅用于你有权测试的端点**。使用本工具探测第三方服务前，请自行确认
  已获得授权，并遵守其服务条款与所在地法律。
- 本工具不构成对任何第三方服务条款、授权或访问权限的授予。
- 使用本工具产生的一切后果由使用者自行承担；作者不对因使用本工具
  导致的任何直接或间接损失承担责任。
- 本工具只输出「接口行为与某模型兼容」这一层的判定，**不构成对后端
  算力的证明**。

## 许可

[Apache License 2.0](LICENSE)，含明确的担保免责（§7）与责任限制（§8）。

内置委派的外部工具 veridrop 为 AGPL-3.0；本仓库仅以子进程调用它，
不包含、不链接其代码，因此本仓库不因该委派而受 AGPL 约束。
