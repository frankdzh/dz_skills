#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多智能体会话日志模糊与语义检索 CLI 主程序 (search_agent_logs.py)

用法:
    python3 search_agent_logs.py <query> [--since 7d] [--until now] [--deep] [--json]

特性:
- 零常驻服务 (Zero-Daemon)，零外部 API 依赖
- 灵活时间窗口过滤 (time_parser)
- 内存 SQLite FTS5 倒排索引毫秒级召回 (fts_engine)
- 混合语义评分与敏感信息脱敏提纯 (semantic_scorer)
- 跨 20+ 款编程智能体异构存储日志解析 (agent_scanner)
- 原生 Markdown 嵌套缩进看板输出与会话接续提示词
"""

import os
import sys
import argparse
import json
import time
from typing import List, Dict, Any, Optional

from time_parser import parse_time_window, format_time_window_desc, format_compact_span, extract_time_intent_and_clean_query
from agent_scanner import scan_all_agents, is_matching_workspace
from fts_engine import FtsEngine
from semantic_scorer import SemanticScorer
from query_processing import normalize_query

def prettify_workspace(ws: str) -> str:
    if not ws:
        return "未知项目"
    home = os.path.expanduser("~")
    clean = ws.replace("file://", "").rstrip("/")
    if clean.startswith(home):
        clean = "~" + clean[len(home):]
    name = os.path.basename(clean.rstrip("/"))
    return f"【{name}】 ({clean})" if name else f"【{clean}】"

def render_markdown_dashboard(
    query: str,
    time_desc: str,
    elapsed_sec: float,
    ranked_sessions: List[Dict[str, Any]],
    current_workspace: str,
    scorer: SemanticScorer,
    cleaned_query: str = "",
    span_desc: str = "",
    total_elapsed: Optional[float] = None
) -> str:
    total_matches = len(ranked_sessions)
    lines = []
    lines.append("### 🔍 会话日志模糊与语义检索看板")
    badge_span = span_desc or "全量"
    if total_elapsed and total_elapsed > 0:
        badge_time = f"[⚡ 交互时延: {total_elapsed:.1f}s (引擎: {elapsed_sec:.2f}s)]"
    else:
        badge_time = f"[⚡ 引擎耗时: {elapsed_sec:.2f}s]"
    lines.append(f"`{badge_time}`  `[🕒 检索跨度: {badge_span}]`  `[📊 命中: {total_matches} 会话]`")
    lines.append(f"> 🎯 检索词: `{query or '全量时间窗口检索'}` | 🕒 窗口明细: {time_desc}\n")

    if not ranked_sessions:
        lines.append("⚠️ **未检索到匹配的会话日志**")
        lines.append("- 建议 1: 扩大时间窗口，例如使用 `--since 30d` 检索更早的历史。")
        lines.append("- 建议 2: 精简搜索关键词或使用空格分词，例如将长句拆为 2~3 个核心词。")
        lines.append("- 建议 3: 加上 `--deep` 开启底层工具调用与完整消息流深度穿透。")
        return "\n".join(lines)

    # 按项目分组
    projects_map: Dict[str, Dict[str, Any]] = {}
    for sess in ranked_sessions:
        ws = sess.get("workspace") or "未知目录"
        is_cur = is_matching_workspace(current_workspace, ws)
        if ws not in projects_map:
            projects_map[ws] = {
                "workspace": ws,
                "is_current": is_cur,
                "agents": {}
            }
        
        agent_name = (sess.get("agent") or "unknown").upper()
        if agent_name not in projects_map[ws]["agents"]:
            projects_map[ws]["agents"][agent_name] = []
        projects_map[ws]["agents"][agent_name].append(sess)

    # 排序：当前项目置顶，其余按最新会话时间排序
    sorted_ws = sorted(
        projects_map.keys(),
        key=lambda w: (
            not projects_map[w]["is_current"],
            -max([s.get("_semantic_score", 0.0) for ag in projects_map[w]["agents"].values() for s in ag])
        )
    )

    for idx, ws in enumerate(sorted_ws):
        if idx > 0:
            lines.append("\n──────────────────────────────────────────────────────────────────────\n")
        
        p_info = projects_map[ws]
        cur_tag = " ★当前仓库" if p_info["is_current"] else ""
        lines.append(f"📁 {prettify_workspace(ws)}{cur_tag}")
        lines.append(f"- 项目路径: `{ws}`")

        for agent_name, sessions in p_info["agents"].items():
            lines.append(f"- 🤖 **{agent_name}** (命中 {len(sessions)} 条会话):")
            for i, s in enumerate(sessions, 1):
                score_pct = s.get("_semantic_score_pct", 0)
                score_tag = f"🌟 [语义相关度 {score_pct}%]" if score_pct >= 60 else f"🔹 [相关度 {score_pct}%]"
                mod_time = s.get("last_modified", "")
                title = s.get("title", "未命名会话")
                conclusion = s.get("last_assistant_turn", "") or s.get("preview", "") or "会话结束"
                if len(conclusion) > 45:
                    conclusion = conclusion[:45] + "..."

                lines.append(f"  - {score_tag} ({mod_time}): {title} ➔ {conclusion}")

                resume_cmd = s.get("resume_command")
                if resume_cmd:
                    lines.append(f"    - ⚡ 恢复命令: `{resume_cmd}`")

                # 提取命中上下文切片（优先使用经过分词与停用词提纯的核心词）
                full_text = f"{title}\n{s.get('last_user_turn', '')}\n{s.get('last_assistant_turn', '')}\n{s.get('deep_content', '')}"
                snippet = scorer.extract_snippet(full_text, cleaned_query or query)
                if snippet:
                    lines.append(f"    - 🔍 命中切片: > \"{snippet}\"")

                t_path = s.get("transcript_path")
                if t_path and os.path.exists(t_path):
                    lines.append(f"    - 📂 日志路径: [transcript.jsonl](file://{t_path})")

    return "\n".join(lines)

def render_compact_dashboard(
    query: str,
    time_desc: str,
    elapsed_sec: float,
    ranked_sessions: List[Dict[str, Any]],
    current_workspace: str,
    scorer: SemanticScorer,
    cleaned_query: str = "",
    span_desc: str = "",
    total_elapsed: Optional[float] = None
) -> str:
    total_matches = len(ranked_sessions)
    lines = []
    lines.append("### 🔍 会话日志检索 (紧凑模式)")
    badge_span = span_desc or "全量"
    if total_elapsed and total_elapsed > 0:
        badge_time = f"[⚡ 交互时延: {total_elapsed:.1f}s (引擎: {elapsed_sec:.2f}s)]"
    else:
        badge_time = f"[⚡ 引擎耗时: {elapsed_sec:.2f}s]"
    lines.append(f"`{badge_time}`  `[🕒 检索跨度: {badge_span}]`  `[📊 命中: {total_matches} 会话]`")
    lines.append(f"> 🎯 检索词: `{query or '全量时间窗口检索'}` | 🕒 窗口明细: {time_desc}\n")

    if not ranked_sessions:
        lines.append("⚠️ **未检索到匹配的会话日志**")
        return "\n".join(lines)

    for s in ranked_sessions:
        score_pct = s.get("_semantic_score_pct", 0)
        agent_name = (s.get("agent") or "UNKNOWN").upper()
        mod_time = s.get("last_modified", "")
        ws = s.get("workspace") or "未知目录"
        is_cur = is_matching_workspace(current_workspace, ws)
        ws_clean = prettify_workspace(ws)
        if is_cur:
            ws_clean += " ★当前"
        title = s.get("title", "未命名会话")
        conclusion = s.get("last_assistant_turn", "") or s.get("preview", "") or "会话结束"
        if len(conclusion) > 40:
            conclusion = conclusion[:40] + "..."
        resume_cmd = s.get("resume_command", "")
        t_path = s.get("transcript_path", "")

        lines.append(f"- **[{agent_name}]** ({score_pct}%) `{mod_time}` | {ws_clean} | {title} ➔ {conclusion}")
        meta_items = []
        if resume_cmd:
            meta_items.append(f"⚡ `{resume_cmd}`")
        if t_path and os.path.exists(t_path):
            meta_items.append(f"📂 [日志](file://{t_path})")
        if meta_items:
            lines.append(f"  {' | '.join(meta_items)}")

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(
        description="多智能体会话日志模糊与语义检索 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("query", nargs="?", default="", help="搜索关键词或短语")
    parser.add_argument("--since", default="7d", help="起始时间 (如 3d, 7d, today, yesterday, 2026-10-15)")
    parser.add_argument("--until", default=None, help="截止时间 (如 now, yesterday, 2026-10-20)")
    parser.add_argument("--project", default="", help="限定工作区物理路径或项目名称")
    parser.add_argument("--agent", default=None, help="限定智能体名称 (如 antigravity, claude, codex, omp)")
    parser.add_argument("--deep", action="store_true", help="启用底层日志与工具调用深度穿透扫描")
    parser.add_argument("--semantic", action="store_true", default=True, help="启用混合语义相关度重排 (默认开启)")
    parser.add_argument("--no-semantic", action="store_false", dest="semantic")
    parser.add_argument("--limit", type=int, default=10, help="最多展示的会话数量 (默认: 10)")
    parser.add_argument("--compact", action="store_true", help="启用紧凑/Token 友好模式，单行输出极简概要")
    parser.add_argument("--total-elapsed", type=float, default=None, help="外部透传的端到端交互总耗时(秒)")
    parser.add_argument("--no-auto-expand", action="store_true", help="禁用无结果时的自动受控阶梯扩围")
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出原始检索数据")

    args = parser.parse_args()
    start_time = time.time()

    search_query = normalize_query(args.query)
    detected_since = None
    detected_until = None

    # 若未显式传入 --since（为默认的 7d）且提供了 query，尝试智能提取时间词
    if args.since == "7d" and args.query:
        cleaned_q, d_since, d_until = extract_time_intent_and_clean_query(args.query)
        if d_since:
            detected_since = d_since
            detected_until = d_until
            search_query = cleaned_q

    # 1. 解析时间窗口
    effective_since = detected_since or args.since
    effective_until = detected_until or args.until
    start_dt, end_dt = parse_time_window(effective_since, effective_until)
    time_desc = format_time_window_desc(start_dt, end_dt)
    span_desc = format_compact_span(start_dt, end_dt)
    current_workspace = os.getcwd()

    # 2. 全域多智能体扫描
    all_sessions = scan_all_agents(
        target_workspace=args.project or current_workspace,
        start_dt=start_dt,
        end_dt=end_dt,
        agent_filter=args.agent,
        deep_scan=args.deep
    )

    # 3. 倒排检索与候选初筛
    fts = FtsEngine()
    fts.index_sessions(all_sessions)

    if search_query:
        candidates = fts.search(search_query, limit=max(50, args.limit * 3))
    else:
        # 未提供 query 时展示时间窗口内最新会话
        candidates = all_sessions[:args.limit]

    # 4. 混合语义重排
    scorer = SemanticScorer(force_math_fallback=True)
    if search_query and args.semantic:
        ranked = scorer.score_and_rank(search_query, candidates)
    else:
        ranked = candidates

    # 4.1 受控自适应阶梯扩围 (方案三)
    # 仅当：提供了 query、未显式指定时间参数/意图、非 deep 模式、且当前 0 命中时触发
    can_auto_expand = (
        bool(search_query)
        and args.since == "7d"
        and detected_since is None
        and args.until is None
        and detected_until is None
        and not args.deep
        and not args.no_auto_expand
    )
    auto_expanded = False
    if not ranked and can_auto_expand:
        start_dt_30d, end_dt_30d = parse_time_window("30d", None)
        all_sessions_30d = scan_all_agents(
            target_workspace=args.project or current_workspace,
            start_dt=start_dt_30d,
            end_dt=end_dt_30d,
            agent_filter=args.agent,
            deep_scan=False
        )
        fts_30d = FtsEngine()
        fts_30d.index_sessions(all_sessions_30d)
        candidates_30d = fts_30d.search(search_query, limit=max(50, args.limit * 3))
        if search_query and args.semantic:
            ranked_30d = scorer.score_and_rank(search_query, candidates_30d)
        else:
            ranked_30d = candidates_30d
        fts_30d.close()

        if ranked_30d:
            ranked = ranked_30d
            start_dt, end_dt = start_dt_30d, end_dt_30d
            time_desc = format_time_window_desc(start_dt, end_dt)
            span_desc = format_compact_span(start_dt, end_dt) + " (自适应扩围)"
            auto_expanded = True

    ranked = ranked[:args.limit]
    elapsed = time.time() - start_time

    # 5. 输出结果
    if args.json:
        payload = {
            "query": args.query,
            "since": str(start_dt),
            "until": str(end_dt),
            "time_window_desc": time_desc,
            "compact_span": span_desc,
            "auto_expanded": auto_expanded,
            "engine_elapsed_seconds": round(elapsed, 4),
            "total_elapsed_seconds": round(args.total_elapsed, 4) if args.total_elapsed else None,
            "total_matches": len(ranked),
            "results": ranked
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif args.compact:
        dashboard = render_compact_dashboard(
            query=args.query,
            time_desc=time_desc,
            elapsed_sec=elapsed,
            ranked_sessions=ranked,
            current_workspace=current_workspace,
            scorer=scorer,
            cleaned_query=search_query,
            span_desc=span_desc,
            total_elapsed=args.total_elapsed
        )
        print(dashboard)
    else:
        dashboard = render_markdown_dashboard(
            query=args.query,
            time_desc=time_desc,
            elapsed_sec=elapsed,
            ranked_sessions=ranked,
            current_workspace=current_workspace,
            scorer=scorer,
            cleaned_query=search_query,
            span_desc=span_desc,
            total_elapsed=args.total_elapsed
        )
        print(dashboard)

    fts.close()

if __name__ == "__main__":
    main()
