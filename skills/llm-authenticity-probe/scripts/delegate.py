#!/usr/bin/env python3
"""外部鉴真工具委派层。

设计约束（不可妥协）:
  1. 凭据只走子进程环境变量 —— 绝不进 argv（ps 可见），绝不落盘。
  2. 第三方代码与 venv 装在外置可配置目录，不占内置盘。
  3. 所有操作幂等，可反复运行。

调用方负责提供 target（已从配置解析出的 baseURL + apiKey），
本层不做任何凭据输入交互。
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys

# 单一临时顶层目录：所有外部工具都装在这一个目录的子目录里，
# 避免每个工具各建一个顶层目录。全部内容可随时整目录删除。
# 默认落在用户缓存目录；想放别处（如外置盘）用 LLM_AUTH_TOOLS_DIR 指定。
DEFAULT_TOOLS_ROOT = os.path.expanduser("~/.cache/llm-authenticity-probe/tools")

# 安装前要求的最小可用空间。veridrop 的 venv 实测数百 MB，留足余量。
MIN_FREE_MB = 1024

TOOLS = {
    "veridrop": {
        "repo": "https://github.com/canarybyte/veridrop.git",
        # 钉死 commit：不信 main，避免上游被改动后自动执行陌生代码。
        "commit": "e87ed92ae37250f87a6503b321c0bc7109618008",
        "commit_date": "2026-09-20",
        "license": "AGPL-3.0",
        "entry": "venv/bin/relay-detector",
        "model_env": "ANTHROPIC_MODEL",
        "key_env": "ANTHROPIC_API_KEY",
        "base_url_env": "ANTHROPIC_BASE_URL",
        # 只装核心依赖；[web] 会拉 FastAPI 等一整套，CLI 用不上。
        "pip_args": ["install", "-e", "."],
        "baselines": ["claude-opus-4-7", "claude-opus-4-6",
                      "claude-sonnet-4-6", "claude-haiku-4-5"],
    },
    "cc-proxy-detector": {
        "repo": "https://github.com/zxc123aa/cc-proxy-detector.git",
        "commit": "98cb298608ae66b9c201aba8608471d9b998add9",
        "commit_date": "2026-02-10",
        "license": "MIT",
        # 无 CLI 入口，直接跑脚本。
        "script": "scripts/detect.py",
        "key_env": "ANTHROPIC_AUTH_TOKEN",
        "base_url_env": "ANTHROPIC_BASE_URL",
        "pip_args": ["install", "requests"],
    },
}

ALIASES = {"ccpd": "cc-proxy-detector", "cc-proxy": "cc-proxy-detector",
           "veridrop": "veridrop"}


def resolve_tool(name):
    """把别名归一成注册表键名，未知则返回 None。"""
    n = name.strip().lower()
    return ALIASES.get(n) or (n if n in TOOLS else None)


def parse_delegates(spec):
    """解析 --delegate 值：'veridrop' / 'ccpd' / 'veridrop,ccpd' / 'all'。"""
    if not spec or spec == "none":
        return []
    if spec.strip().lower() == "all":
        return list(TOOLS)
    out = []
    for part in spec.split(","):
        if not part.strip():
            continue
        r = resolve_tool(part)
        if r and r not in out:
            out.append(r)
    return out


def tools_root():
    return os.environ.get("LLM_AUTH_TOOLS_DIR") or DEFAULT_TOOLS_ROOT


def tool_dir(name):
    return os.path.join(tools_root(), name)


def entry_path(name):
    return os.path.join(tool_dir(name), TOOLS[name]["entry"])


def _nearest_existing(path):
    probe = path
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            return None
        probe = parent
    return probe


def _free_mb(path):
    probe = _nearest_existing(path)
    if not probe:
        return None
    try:
        return shutil.disk_usage(probe).free // (1024 * 1024)
    except OSError:
        return None


def _mount_of(path):
    m = _nearest_existing(path) or path
    while m and not os.path.ismount(m):
        parent = os.path.dirname(m)
        if parent == m:
            break
        m = parent
    return m


def preflight(name):
    """安装前检查：目标卷存在、可写、空间够。返回 (ok, 消息)。

    注意：判可写性必须看目标目录本身，而不是卷根 ——
    外置盘卷根常为 root:wheel 775，普通用户不可写，但其子目录可写。
    """
    root = tools_root()
    target = _nearest_existing(root) or _mount_of(root)
    if not target or not os.path.isdir(target):
        return False, (f"安装目录所在卷未挂载：{root}\n"
                       f"外置盘未插入时无法安装或委派。"
                       f"可用 LLM_AUTH_TOOLS_DIR 指定其他位置。")
    if not os.access(target, os.W_OK):
        return False, f"目标目录不可写：{target}"

    probe = os.path.join(target, ".wtest")
    try:
        with open(probe, "w"):
            pass
        os.remove(probe)
    except OSError as e:
        return False, f"目标目录不可写：{target}（{e.strerror}）"

    free = _free_mb(root)
    if free is not None and free < MIN_FREE_MB:
        return False, f"可用空间不足：{free}MB < {MIN_FREE_MB}MB（{target}）"
    return True, f"空闲 {free}MB @ {target}" if free is not None else f"@{target}"


def _entry_runs(name):
    """入口是否真正可执行 —— 以实际执行为准。

    不要试图解析脚本路径：macOS 的 venv 用 `#!/bin/sh` 包装器，
    失效的旧路径写在正文第 2 行而非 shebang，任何静态检查都会漏判。
    只有真跑一次才能确定。
    """
    spec = TOOLS[name]
    if "entry" not in spec:
        return False
    path = entry_path(name)
    if not os.path.isfile(path):
        return False
    try:
        r = subprocess.run([path, "--help"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def _script_ready(name):
    """脚本型工具是否可用：venv 解释器能跑 + 脚本在位。"""
    spec = TOOLS[name]
    if "script" not in spec:
        return False
    py = venv_python(name)
    script = os.path.join(tool_dir(name), spec["script"])
    if not (os.path.isfile(py) and os.path.isfile(script)):
        return False
    try:
        r = subprocess.run([py, "-c", "pass"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def venv_python(name):
    return os.path.join(tool_dir(name), "venv", "bin", "python")


def is_installed(name):
    spec = TOOLS[name]
    if "entry" in spec:
        return _entry_runs(name)
    return _script_ready(name)


def _run(cmd, cwd=None, env=None, timeout=1800, log=print):
    """执行子进程，实时透传输出。返回 (returncode, 合并输出)。"""
    log(f"    $ {shlex.join(cmd)}")
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    except subprocess.TimeoutExpired:
        return 124, "超时"
    if p.stdout:
        for line in p.stdout.rstrip().splitlines()[-40:]:
            log(f"      {line}")
    return p.returncode, p.stdout or ""


def _snapshot_deps(name, log=print):
    """把实际解析到的依赖版本落盘，供复现与审计核对。"""
    py = venv_python(name)
    try:
        p = subprocess.run([py, "-m", "pip", "freeze"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        log("  ! 依赖快照失败，不影响安装")
        return
    if p.returncode != 0:
        log("  ! 依赖快照失败，不影响安装")
        return
    path = os.path.join(tool_dir(name), "requirements.lock.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(p.stdout)
    log(f"  依赖快照：{path}")


def install(name, log=print):
    """克隆 + 建 venv + 装依赖。幂等：已装则跳过，失效则自愈重建。"""
    spec = TOOLS[name]
    dest = tool_dir(name)

    if is_installed(name):
        log(f"  {name} 已安装：{entry_path(name) if 'entry' in spec else venv_python(name)}")
        return True

    ok, msg = preflight(name)
    if not ok:
        log(f"  ✗ {name} 无法安装：{msg}")
        return False
    log(f"  {name} 安装目标 {dest}（{msg}）")
    log(f"  许可：{spec['license']} · 钉定 {spec['commit_date']} {spec['commit'][:8]}")

    os.makedirs(tools_root(), exist_ok=True)

    if not os.path.isdir(os.path.join(dest, ".git")):
        if os.path.isdir(dest):
            log(f"  清理不完整目录 {dest}")
            shutil.rmtree(dest)
        rc, _ = _run(["git", "clone", spec["repo"], dest], log=log)
        if rc != 0:
            log("  ✗ clone 失败（网络？需要代理时请确认 http_proxy）")
            return False

    rc, _ = _run(["git", "-C", dest, "checkout", "--detach",
                  spec["commit"]], log=log)
    if rc != 0:
        log(f"  ✗ 切换到 {spec['commit'][:8]} 失败")
        return False

    venv = os.path.join(dest, "venv")
    # 走到这里说明入口跑不通（is_installed 已在上方返回）。若 venv 目录
    # 仍在，只能是目录被移动过导致路径失效，整体重建而非修补。
    if os.path.isdir(venv):
        log("    venv 已失效（目录被移动过），重建")
        shutil.rmtree(venv)
    if not os.path.isfile(os.path.join(venv, "bin", "python")):
        rc, _ = _run([sys.executable, "-m", "venv", venv], log=log)
        if rc != 0:
            log("  ✗ venv 创建失败（文件系统需支持符号链接，"
                "exFAT/FAT32 会失败）")
            return False

    # 一律用 python -m pip：venv/bin/pip 的 shebang 可能是失效的旧路径。
    py = os.path.join(venv, "bin", "python")
    _run([py, "-m", "pip", "install", "-q", "--upgrade", "pip"], log=log)
    rc, _ = _run([py, "-m", "pip"] + spec["pip_args"], cwd=dest, log=log)
    if rc != 0:
        log("  ✗ 依赖安装失败")
        return False

    if not is_installed(name):
        log(f"  ✗ 安装后仍不可用（{name}）")
        return False
    _snapshot_deps(name, log=log)
    log(f"  ✓ {name} 安装完成")
    return True


def base_root(messages_url):
    """把 /v1/messages 端点还原成根 URL —— veridrop 要的是中转站根地址。"""
    b = messages_url.rstrip("/")
    for suffix in ("/v1/messages", "/v1/chat/completions", "/messages"):
        if b.endswith(suffix):
            b = b[: -len(suffix)]
            break
    if b.endswith("/v1"):
        b = b[: -len("/v1")]
    return b.rstrip("/")


def has_baseline(name, model):
    return any(model == b or model.startswith(b) for b in TOOLS[name]["baselines"])


def build_env(name, target):
    """构造子进程环境：凭据只进环境变量，绝不进 argv。

    同时确保目标主机绕过系统代理 —— 内网/本地端点走代理会把连接失败
    伪装成 502，产生假阴性。
    """
    spec = TOOLS[name]
    env = dict(os.environ)
    root_url = base_root(target["baseURL"])
    env[spec["key_env"]] = target["apiKey"]
    env[spec["base_url_env"]] = root_url
    if "model_env" in spec and target.get("model"):
        env[spec["model_env"]] = target["model"]
    host = root_url.split("//", 1)[-1].split("/")[0]
    for k in ("NO_PROXY", "no_proxy"):
        env[k] = (env.get(k, "") + "," + host).strip(",")
    return env, root_url


def run_ccpd(target, model, log=print, rounds=1):
    """用 cc-proxy-detector 溯源渠道（Anthropic / Bedrock / Vertex）。"""
    name = "cc-proxy-detector"
    if not is_installed(name):
        log(f"  {name} 未安装，先执行 --install-tools")
        return False, ""

    env, root_url = build_env(name, target)
    script = os.path.join(tool_dir(name), TOOLS[name]["script"])
    log(f"  溯源 {root_url} model={model} rounds={rounds}")
    rc, txt = _run([venv_python(name), script, "--base-url", root_url,
                    "--scan-models", model, "--rounds", str(rounds)],
                   cwd=tool_dir(name), env=env, log=log, timeout=600)
    if rc != 0:
        return False, ""

    # 从输出里提取渠道判定行，供汇总引用。
    verdicts = [l.strip() for l in (txt or "").splitlines()
                if "Antigravity" in l or "Bedrock" in l
                or "Anthropic" in l and "置信度" in l]
    return True, (verdicts[0] if verdicts else "")


def run_veridrop(target, model, mode="full", log=print, workdir=None):
    """对 target 跑 veridrop detect（+ compare，若有基线）。

    target: {"baseURL":..., "apiKey":...}
    返回 (ok, 结论文本)
    """
    if not is_installed("veridrop"):
        log("  veridrop 未安装，先执行 --install-tools")
        return False, ""

    # 不直接用 relay-detector 入口：上游 e87ed92 在 OpenAI/GPT 协议的
    # protocol 检测里把 issues 产出为 dict，render_terminal 会 TypeError，
    # 且渲染在 write_json 之前 → JSON 报告写不出来。走兼容层绕开该 bug。
    entry = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "veridrop_shim.py")
    env, root_url = build_env("veridrop", target)

    out_dir = workdir or os.path.join(tools_root(), "reports")
    os.makedirs(out_dir, exist_ok=True)
    # 写到独立 reports/ 目录，不落进被钉定的仓库 —— 否则 last_report.json
    # 会让 `git status` 变脏，且该文件名不在上游 .gitignore 覆盖范围内。
    out = os.path.join(out_dir, f"{model.replace('/', '_')}_report.json")
    log(f"  探测 {root_url} model={model} mode={mode}")
    rc, _ = _run([venv_python("veridrop"), entry, "detect",
                  "--base-url", root_url,
                  "--model", model, "--mode", mode, "-o", out],
                 env=env, log=log, timeout=600)
    if rc != 0 or not os.path.isfile(out):
        return False, ""

    if has_baseline("veridrop", model):
        log("  与官方基线对比")
        # 必须在工具目录下执行：veridrop 按相对路径 data/baselines 找基线，
        # 继承调用方的 cwd 会找不到（明明存在却报缺失）。
        rc2, _ = _run([venv_python("veridrop"), entry, "compare", out],
                      cwd=tool_dir("veridrop"), env=env, log=log, timeout=300)
        if rc2 == 0:
            return True, "基线对比完成（见上方差异表）"
        log("  ⚠ 基线对比失败")
    else:
        log(f"  （{model} 无预置基线，跳过 compare）")

    note = _explain_veridrop_report(out, model, log)
    return True, note


def _strip_route_prefix(name):
    """去一层路由前缀与 [..] 修饰：cx/gpt-6-luna → gpt-6-luna。"""
    s = (name or "").strip()
    if "/" in s:
        s = s.rsplit("/", 1)[-1]
    return re.sub(r"\[.*?\]$", "", s)


def _explain_veridrop_report(path, model, log):
    """读取 veridrop JSON，把「模型名前缀差异」与「真实替换」区分开。

    veridrop 按字面比较 response.model 与请求的 model，遇到中转站加路由
    前缀（cx/gpt-6-luna vs gpt-6-luna）会判 model_mismatch 并扣分；这不是
    模型被替换。这里给出解读，避免把前缀差异读成掺水。
    """
    try:
        with open(path, encoding="utf-8") as f:
            rep = json.load(f)
    except (OSError, json.JSONDecodeError):
        return ""

    total, verdict = rep.get("total_score"), rep.get("verdict")
    prefix_only, real = 0, []
    for r in rep.get("results") or []:
        for issue in (r.get("details") or {}).get("issues") or []:
            if not isinstance(issue, dict) or issue.get("code") != "model_mismatch":
                continue
            exp, act = issue.get("expected") or "", issue.get("actual") or ""
            if act and _strip_route_prefix(act).lower() == _strip_route_prefix(exp).lower():
                prefix_only += 1
            else:
                real.append(f"{exp} → {act}")

    parts = []
    if total is not None:
        parts.append(f"veridrop 总分 {total}（{verdict}）")
    if prefix_only:
        parts.append(f"其中 {prefix_only} 处 model_mismatch 只是路由前缀差异"
                     "（非模型替换），不构成掺水证据")
    if real:
        parts.append("真实模型名不符：" + "；".join(dict.fromkeys(real))[:120])
    note = "；".join(parts)
    if note:
        log(f"  解读：{note}")
    return note


RUNNERS = {"veridrop": run_veridrop, "cc-proxy-detector": run_ccpd}
