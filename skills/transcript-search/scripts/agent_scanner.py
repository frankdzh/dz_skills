#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨 20+ 款编程智能体异构存储日志解析器 (Agent Log Scanner)

复用并演进 workday-recall 核心扫描器架构：
- 支持自定义时间区间 (start_dt, end_dt)
- 支持数据库型 (Antigravity, OMP, OpenCode) 与文件型 (Claude, Codex, Pi, Cursor, Generic)
- 支持 --deep 模式下底层 transcript.jsonl 的逐行流式深度提取 (带 20MB 大文件与 1.5s 熔断保护)
"""

import os
import sys
import glob
import json
import sqlite3
import datetime
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from query_processing import is_search_skill_invocation, is_search_dashboard_output, is_pure_search_session

MAX_FILE_BYTES = 20 * 1024 * 1024  # 20MB 上限
MAX_STREAMING_LINES = 2000          # 单文件最多流式提取 2000 行

def get_resume_command(agent: str, session_id: str) -> Optional[str]:
    """根据智能体类型与会话 ID 生成对应的终端恢复命令"""
    if not agent or not session_id:
        return None
    ag = agent.lower().strip()
    if ag == "claude":
        return f"claude --resume {session_id}"
    elif ag == "codex":
        return f"codex resume {session_id}"
    elif ag == "antigravity":
        return f"agy --conversation {session_id}"
    elif ag == "omp":
        return f"omp --resume {session_id}"
    elif ag == "pi":
        return f"pi --resume {session_id}"
    return None

def is_matching_workspace(target_ws: str, session_ws: str) -> bool:
    if not target_ws or not session_ws:
        return False
    try:
        t = os.path.realpath(os.path.expanduser(target_ws)).rstrip("/")
        s = os.path.realpath(os.path.expanduser(session_ws)).rstrip("/")
        return t == s or t.startswith(s + "/") or s.startswith(t + "/")
    except Exception:
        return target_ws.rstrip("/") == session_ws.rstrip("/")

def clean_text_snippet(text: Any, max_len: int = 80) -> str:
    if not text:
        return ""
    s = re.sub(r"\s+", " ", str(text)).strip()
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s

def extract_deep_transcript_content(filepath: str) -> str:
    """流式提取 transcript.jsonl 中的工具调用命令与重要消息（自动忽略检索技能命令与看板输出）"""
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        if os.path.getsize(filepath) > MAX_FILE_BYTES:
            return "[超大日志文件，已跳过全文穿透]"
    except Exception:
        return ""

    extracted = []
    line_count = 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_count += 1
                if line_count > MAX_STREAMING_LINES:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    # 1. Antigravity 格式
                    if "tool_calls" in record and record["tool_calls"]:
                        for tc in record["tool_calls"]:
                            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                            cmd = fn.get("CommandLine") or fn.get("command") or fn.get("path") or ""
                            if cmd:
                                if "search_agent_logs.py" in cmd:
                                    continue
                                extracted.append(f"执行工具 {fn.get('name', '')}: {cmd}")
                    # 2. Claude 格式
                    elif record.get("type") == "assistant":
                        msg = record.get("message", {})
                        c = msg.get("content", "")
                        if isinstance(c, list):
                            for p in c:
                                if isinstance(p, dict) and p.get("type") == "tool_use":
                                    inp = p.get("input", {})
                                    cmd = inp.get("command") or inp.get("description") or ""
                                    if "search_agent_logs.py" in cmd:
                                        continue
                                    extracted.append(f"执行工具 {p.get('name', '')}: {cmd}")
                    # 3. OMP / Pi 格式 (type == 'message')
                    elif record.get("type") == "message":
                        msg = record.get("message", {})
                        role = msg.get("role", "")
                        c = msg.get("content", "")
                        if isinstance(c, list):
                            for p in c:
                                if isinstance(p, dict):
                                    if p.get("type") == "text":
                                        t_val = str(p.get("text", "")).strip()
                                        if t_val and not t_val.startswith("<environment_context>") and not t_val.startswith("# AGENTS.md"):
                                            if not is_search_skill_invocation(t_val) and not is_search_dashboard_output(t_val):
                                                extracted.append(f"{role}: {t_val[:200]}")
                                    elif p.get("type") == "toolCall":
                                        args_str = str(p.get("args", ""))
                                        if "search_agent_logs.py" not in args_str:
                                            extracted.append(f"执行工具 {p.get('name', '')}: {args_str[:150]}")
                        elif isinstance(c, str) and c:
                            if not c.startswith("<environment_context>") and not c.startswith("# AGENTS.md"):
                                if not is_search_skill_invocation(c) and not is_search_dashboard_output(c):
                                    extracted.append(f"{role}: {c[:200]}")
                    # 4. 提取常规消息内容
                    c = record.get("content") or record.get("text") or ""
                    if isinstance(c, str) and c:
                        # 过滤冗长环境上下文与检索技能输出
                        if not c.startswith("<environment_context>") and not c.startswith("# AGENTS.md"):
                            if not is_search_skill_invocation(c) and not is_search_dashboard_output(c):
                                if len(c) > 200:
                                    c = c[:200]
                                extracted.append(c)
                except Exception:
                    continue
    except Exception:
        pass

    return "\n".join(extracted[:60])

# ==============================================================================
# 1. Antigravity (Gemini CLI)
# ==============================================================================
def scan_antigravity_sessions_from_dir(
    db_path: str, brain_dir: str, target_workspace: str,
    start_dt: datetime.datetime, end_dt: datetime.datetime,
    deep_scan: bool = False
) -> List[Dict[str, Any]]:
    if not os.path.exists(db_path):
        return []

    results = []
    start_iso = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_iso = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT conversation_id, title, preview, datetime(last_modified_time, 'localtime') as local_mod_time, workspace_uris, step_count
        FROM conversation_summaries
        WHERE datetime(last_modified_time, 'localtime') >= datetime(?)
          AND datetime(last_modified_time, 'localtime') <= datetime(?)
        ORDER BY last_modified_time DESC
        """
        cursor.execute(query, (start_iso, end_iso))
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        return []

    for cid, title, preview, local_mod, ws_uris_raw, steps in rows:
        session_ws = ""
        is_target_ws = False
        try:
            uris = json.loads(ws_uris_raw) if ws_uris_raw else []
            if uris:
                clean_first = uris[0].replace("file://", "")
                session_ws = clean_first
                for u in uris:
                    clean_u = u.replace("file://", "")
                    if target_workspace and is_matching_workspace(target_workspace, clean_u):
                        is_target_ws = True
                        session_ws = clean_u
                        break
        except Exception:
            pass

        transcript_path = os.path.join(brain_dir, cid, ".system_generated", "logs", "transcript.jsonl")
        last_user, last_model = "", ""
        user_prompts_labeled = []
        total_user_turns = 0
        has_non_search_user_turn = False
        
        if os.path.exists(transcript_path):
            try:
                with open(transcript_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            record = json.loads(line)
                            t, s, c = record.get("type"), record.get("source"), record.get("content", "")
                            if (s in ("USER_EXPLICIT", "USER") and t in ("USER_INPUT", "REQUEST")) or t == "USER_INPUT":
                                if "<USER_REQUEST>" in c:
                                    start_tag = c.find("<USER_REQUEST>") + len("<USER_REQUEST>")
                                    end_tag = c.find("</USER_REQUEST>", start_tag)
                                    u_text = c[start_tag:end_tag if end_tag != -1 else None].strip()
                                else:
                                    u_text = c.strip()
                                if u_text:
                                    total_user_turns += 1
                                    if is_search_skill_invocation(u_text):
                                        continue
                                    has_non_search_user_turn = True
                                    user_prompts_labeled.append(f"[第 {len(user_prompts_labeled)+1} 轮提问] {u_text}")
                                    last_user = u_text
                            elif (s == "MODEL" and t == "PLANNER_RESPONSE") or (t == "PLANNER_RESPONSE" and c):
                                if not is_search_dashboard_output(c):
                                    last_model = c.strip()
                        except Exception:
                            continue
            except Exception:
                pass

        # 始终跳过当前正在执行检索的会话本身，杜绝自引用干扰
        cur_cid = os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
        if cur_cid and cid == cur_cid:
            continue

        # 排除纯检索执行会话，杜绝搜索回声与自引污染
        if is_pure_search_session(
            total_user_turns,
            has_non_search_user_turn,
            title=title or "",
            preview=preview or "",
            last_assistant=last_model
        ):
            continue

        all_user_text = "\n".join(user_prompts_labeled)
        if deep_scan:
            deep_content = f"{all_user_text}\n{extract_deep_transcript_content(transcript_path)}".strip()
        else:
            deep_content = all_user_text

        results.append({
            "agent": "antigravity",
            "session_id": cid,
            "resume_command": get_resume_command("antigravity", cid),
            "title": title or "Antigravity 会话",
            "preview": preview,
            "workspace": session_ws or "未知目录",
            "last_modified": str(local_mod),
            "is_current_workspace": is_target_ws,
            "transcript_path": transcript_path if os.path.exists(transcript_path) else None,
            "last_user_turn": last_user,
            "last_assistant_turn": last_model,
            "deep_content": deep_content
        })
    return results

def scan_antigravity_sessions(target_ws: str, start_dt: datetime.datetime, end_dt: datetime.datetime, deep_scan: bool = False):
    home = os.path.expanduser("~")
    db_path = os.path.join(home, ".gemini", "antigravity-cli", "conversation_summaries.db")
    brain_dir = os.path.join(home, ".gemini", "antigravity-cli", "brain")
    return scan_antigravity_sessions_from_dir(db_path, brain_dir, target_ws, start_dt, end_dt, deep_scan)

# ==============================================================================
# 2. Claude Code
# ==============================================================================
def scan_claude_sessions_from_dir(
    base_dir: str, target_workspace: str,
    start_dt: datetime.datetime, end_dt: datetime.datetime,
    deep_scan: bool = False
) -> List[Dict[str, Any]]:
    projects_dir = os.path.join(base_dir, "projects") if os.path.basename(base_dir) != "projects" else base_dir
    if not os.path.exists(projects_dir):
        return []

    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    results = []

    for filepath in glob.glob(os.path.join(projects_dir, "*", "*.jsonl")):
        if "subagents" in filepath:
            continue
        try:
            mtime = os.path.getmtime(filepath)
            if mtime < start_ts or mtime > end_ts:
                continue

            parent_dir_name = os.path.basename(os.path.dirname(filepath))
            inferred_ws = "/" + parent_dir_name.strip("-").replace("-", "/") if parent_dir_name.startswith("-") else parent_dir_name
            session_id = Path(filepath).stem
            actual_cwd, ai_title, first_user, last_user, last_assistant = "", "", "", "", ""
            user_prompts_labeled = []
            total_user_turns = 0
            has_non_search_user_turn = False
            
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        record = json.loads(line)
                        t = record.get("type")
                        if not actual_cwd and record.get("cwd"):
                            actual_cwd = record.get("cwd")
                        if t == "ai-title" and record.get("aiTitle"):
                            ai_title = record.get("aiTitle")
                        elif t == "last-prompt" and record.get("lastPrompt"):
                            lp = record.get("lastPrompt", "")
                            if not is_search_skill_invocation(lp):
                                last_user = lp
                                if not first_user: first_user = last_user
                        elif t == "user":
                            msg = record.get("message", {})
                            c = msg.get("content", "")
                            if isinstance(c, list):
                                c = " ".join([p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text"])
                            if c:
                                u_text = str(c).strip()
                                total_user_turns += 1
                                if is_search_skill_invocation(u_text):
                                    continue
                                has_non_search_user_turn = True
                                user_prompts_labeled.append(f"[第 {len(user_prompts_labeled)+1} 轮提问] {u_text}")
                                if not first_user: first_user = u_text
                                last_user = u_text
                        elif t == "assistant":
                            msg = record.get("message", {})
                            c = msg.get("content", "")
                            if isinstance(c, list):
                                parts = [p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text"]
                                c = "\n".join(parts)
                            if c and not is_search_dashboard_output(c):
                                last_assistant = str(c).strip()
                    except Exception:
                        continue

            cur_claude_sid = os.environ.get("CLAUDE_CONVERSATION_ID") or os.environ.get("CLAUDE_SESSION_ID")
            if cur_claude_sid and session_id == cur_claude_sid:
                continue

            if is_pure_search_session(
                total_user_turns,
                has_non_search_user_turn,
                title=ai_title or first_user or "",
                last_assistant=last_assistant
            ):
                continue

            final_ws = actual_cwd or inferred_ws
            is_target = target_workspace and is_matching_workspace(target_workspace, final_ws)
            mod_dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

            session_title = f"Claude 会话 ({session_id[:8]})"
            if ai_title:
                session_title = f"Claude: {ai_title}"
            elif first_user:
                session_title = f"Claude: {clean_text_snippet(first_user, 32)}"

            all_user_text = "\n".join(user_prompts_labeled)
            deep_content = f"{all_user_text}\n{extract_deep_transcript_content(filepath)}".strip() if deep_scan else all_user_text

            results.append({
                "agent": "claude",
                "session_id": session_id,
                "resume_command": get_resume_command("claude", session_id),
                "title": session_title,
                "workspace": final_ws or "未知目录",
                "last_modified": mod_dt,
                "is_current_workspace": bool(is_target),
                "transcript_path": filepath,
                "last_user_turn": last_user,
                "last_assistant_turn": last_assistant,
                "deep_content": deep_content
            })
        except Exception:
            continue
    return results

def scan_claude_sessions(target_ws: str, start_dt: datetime.datetime, end_dt: datetime.datetime, deep_scan: bool = False):
    home = os.path.expanduser("~")
    base_dir = os.path.join(home, ".claude", "projects")
    return scan_claude_sessions_from_dir(base_dir, target_ws, start_dt, end_dt, deep_scan)

# ==============================================================================
# 3. OMP (Oh My Pi)
# ==============================================================================
def scan_omp_sessions(target_ws: str, start_dt: datetime.datetime, end_dt: datetime.datetime, deep_scan: bool = False) -> List[Dict[str, Any]]:
    home = os.path.expanduser("~")
    db_path = os.path.join(home, ".omp", "agent", "history.db")
    if not os.path.exists(db_path):
        return []

    results = []
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 1. 聚合 session_recaps (全量记录)
        recaps_map: Dict[str, Dict[str, Any]] = {}
        try:
            cursor.execute("SELECT session_id, cwd, recap, created_at FROM session_recaps ORDER BY created_at ASC")
            for sid, cwd, recap, cat in cursor.fetchall():
                if sid not in recaps_map:
                    recaps_map[sid] = {"cwd": cwd, "recaps": [], "last_recap": "", "time": cat}
                if cwd:
                    recaps_map[sid]["cwd"] = cwd
                if recap:
                    recaps_map[sid]["recaps"].append(recap)
                    recaps_map[sid]["last_recap"] = recap
                recaps_map[sid]["time"] = cat
        except Exception:
            pass

        # 2. 聚合 history 中全部用户 prompt
        history_cwd_map: Dict[str, str] = {}
        history_prompts_map: Dict[str, List[str]] = {}
        history_ts_map: Dict[str, int] = {}
        try:
            cursor.execute("SELECT session_id, cwd, prompt, created_at FROM history WHERE session_id IS NOT NULL ORDER BY id ASC")
            for sid, cwd, prompt, cat in cursor.fetchall():
                if cwd:
                    history_cwd_map[sid] = cwd
                if prompt:
                    history_prompts_map.setdefault(sid, []).append(prompt)
                if cat:
                    history_ts_map[sid] = cat
        except Exception:
            pass

        # 3. 获取 session_titles
        session_meta: Dict[str, Dict[str, Any]] = {}
        try:
            cursor.execute("SELECT session_id, title, updated_at FROM session_titles")
            for sid, title, up_ts in cursor.fetchall():
                session_meta[sid] = {"title": title, "updated_at": up_ts}
        except Exception:
            pass
        conn.close()

        # 圈定在 [start_ts, end_ts] 期间活跃的所有 session_id
        active_sids = set()
        for sid, meta in session_meta.items():
            if start_ts <= meta.get("updated_at", 0) <= end_ts:
                active_sids.add(sid)
        for sid, r_info in recaps_map.items():
            if start_ts <= r_info.get("time", 0) <= end_ts:
                active_sids.add(sid)
        for sid, cat in history_ts_map.items():
            if start_ts <= cat <= end_ts:
                active_sids.add(sid)

        # 4. 组装会话详情
        for sid in active_sids:
            recap_info = recaps_map.get(sid, {})
            session_ws = recap_info.get("cwd") or history_cwd_map.get(sid, "")
            recap_list = recap_info.get("recaps", [])
            last_recap = recap_info.get("last_recap", "")
            
            sid_prompts = history_prompts_map.get(sid, [])
            valid_prompts = []
            total_user_turns = len(sid_prompts)
            for p in sid_prompts:
                if not is_search_skill_invocation(p):
                    valid_prompts.append(p)
            has_non_search_user_turn = bool(valid_prompts)

            valid_recaps = [r for r in recap_list if not is_search_dashboard_output(r)]
            last_recap_candidate = last_recap if not is_search_dashboard_output(last_recap) else (valid_recaps[-1] if valid_recaps else "")

            meta = session_meta.get(sid, {})
            title_meta = meta.get("title") or ""

            if is_pure_search_session(
                total_user_turns,
                has_non_search_user_turn,
                title=title_meta,
                last_assistant=last_recap_candidate
            ):
                continue

            last_prompt = valid_prompts[-1] if valid_prompts else ""
            first_prompt = valid_prompts[0] if valid_prompts else ""
            title = title_meta or (f"OMP: {clean_text_snippet(first_prompt, 32)}" if first_prompt else f"OMP 会话 ({sid[:8]})")
            
            up_ts = meta.get("updated_at") or recap_info.get("time") or history_ts_map.get(sid, start_ts)
            mod_dt = datetime.datetime.fromtimestamp(up_ts).strftime("%Y-%m-%d %H:%M:%S")
            is_target = target_ws and is_matching_workspace(target_ws, session_ws)

            # 定位实际 transcript.jsonl 路径
            transcript_path = None
            try:
                matches = glob.glob(os.path.join(home, ".omp", "agent", "sessions", "**", f"*{sid}*.jsonl"), recursive=True)
                if matches:
                    transcript_path = matches[0]
            except Exception:
                pass

            # 构建内容：内置聚合全量 prompts 与 recaps，标注交互轮次
            sid_prompts_labeled = [f"[第 {idx} 轮提问] {p}" for idx, p in enumerate(valid_prompts, 1)]
            recap_list_labeled = [f"[阶段小结] {r}" for r in valid_recaps]
            all_prompts_recap_text = "\n".join(sid_prompts_labeled + recap_list_labeled)
            if deep_scan and transcript_path and os.path.exists(transcript_path):
                file_deep = extract_deep_transcript_content(transcript_path)
                deep_content = f"{all_prompts_recap_text}\n{file_deep}".strip()
            else:
                deep_content = all_prompts_recap_text

            results.append({
                "agent": "omp",
                "session_id": sid,
                "resume_command": get_resume_command("omp", sid),
                "title": title,
                "workspace": session_ws or "未知目录",
                "last_modified": mod_dt,
                "is_current_workspace": bool(is_target),
                "transcript_path": transcript_path,
                "last_user_turn": last_prompt,
                "last_assistant_turn": last_recap_candidate,
                "deep_content": deep_content
            })
    except Exception:
        pass
    return results

# ==============================================================================
# 4. Pi (Native CLI)
# ==============================================================================
def scan_pi_sessions(target_ws: str, start_dt: datetime.datetime, end_dt: datetime.datetime, deep_scan: bool = False) -> List[Dict[str, Any]]:
    home = os.path.expanduser("~")
    base_dir = os.path.join(home, ".pi", "agent", "sessions")
    if not os.path.exists(base_dir):
        return []

    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    results = []

    for filepath in glob.glob(os.path.join(base_dir, "**", "*.jsonl"), recursive=True):
        try:
            mtime = os.path.getmtime(filepath)
            if mtime < start_ts or mtime > end_ts:
                continue

            session_id = Path(filepath).stem.split("_")[-1]
            actual_cwd, session_title, first_user, last_user, last_assistant = "", "", "", "", ""
            user_prompts_labeled = []
            total_user_turns = 0
            has_non_search_user_turn = False

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        record = json.loads(line)
                        t = record.get("type")
                        if not actual_cwd and record.get("cwd"):
                            actual_cwd = record.get("cwd")
                        if t == "title" and record.get("title"):
                            session_title = record.get("title")
                        elif t == "message":
                            msg = record.get("message", {})
                            role = msg.get("role")
                            content = msg.get("content", "")
                            text_body = ""
                            if isinstance(content, list):
                                text_body = " ".join([p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"])
                            elif isinstance(content, str):
                                text_body = content
                            
                            if text_body:
                                if role == "user":
                                    u_text = text_body.strip()
                                    total_user_turns += 1
                                    if is_search_skill_invocation(u_text):
                                        continue
                                    has_non_search_user_turn = True
                                    user_prompts_labeled.append(f"[第 {len(user_prompts_labeled)+1} 轮提问] {u_text}")
                                    if not first_user: first_user = u_text
                                    last_user = u_text
                                elif role == "assistant":
                                    if not is_search_dashboard_output(text_body):
                                        last_assistant = text_body.strip()
                    except Exception:
                        continue

            if is_pure_search_session(
                total_user_turns,
                has_non_search_user_turn,
                title=session_title or first_user or "",
                last_assistant=last_assistant
            ):
                continue

            is_target = target_ws and is_matching_workspace(target_ws, actual_cwd)
            mod_dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            title = session_title or (f"Pi: {clean_text_snippet(first_user, 32)}" if first_user else f"Pi 会话 ({session_id[:8]})")
            all_user_text = "\n".join(user_prompts_labeled)
            deep_content = f"{all_user_text}\n{extract_deep_transcript_content(filepath)}".strip() if deep_scan else all_user_text

            results.append({
                "agent": "pi",
                "session_id": session_id,
                "resume_command": get_resume_command("pi", session_id),
                "title": title,
                "workspace": actual_cwd or "未知目录",
                "last_modified": mod_dt,
                "is_current_workspace": bool(is_target),
                "transcript_path": filepath,
                "last_user_turn": last_user,
                "last_assistant_turn": last_assistant,
                "deep_content": deep_content
            })
        except Exception:
            continue
    return results

# ==============================================================================
# 5. Codex
# ==============================================================================
def scan_codex_sessions(target_ws: str, start_dt: datetime.datetime, end_dt: datetime.datetime, deep_scan: bool = False) -> List[Dict[str, Any]]:
    home = os.path.expanduser("~")
    base_dir = os.path.join(home, ".codex", "sessions")
    if not os.path.exists(base_dir):
        return []

    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    results = []

    for filepath in glob.glob(os.path.join(base_dir, "**", "rollout-*.jsonl"), recursive=True):
        try:
            mtime = os.path.getmtime(filepath)
            if mtime < start_ts or mtime > end_ts:
                continue

            session_id = Path(filepath).stem
            actual_cwd, first_user, last_user, last_assistant = "", "", "", ""
            user_prompts_labeled = []
            total_user_turns = 0
            has_non_search_user_turn = False

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        record = json.loads(line)
                        p = record.get("payload", {})
                        t = p.get("type")
                        if not actual_cwd and p.get("cwd"):
                            actual_cwd = p.get("cwd")
                        if t == "UserMessage":
                            msg = p.get("message", "")
                            if msg and not msg.startswith("# AGENTS.md instructions"):
                                u_text = msg.strip()
                                total_user_turns += 1
                                if is_search_skill_invocation(u_text):
                                    continue
                                has_non_search_user_turn = True
                                user_prompts_labeled.append(f"[第 {len(user_prompts_labeled)+1} 轮提问] {u_text}")
                                if not first_user: first_user = u_text
                                last_user = u_text
                        elif t in ("AgentMessage", "task_complete"):
                            msg = str(p.get("message") or p.get("summary") or "").strip()
                            if not is_search_dashboard_output(msg):
                                last_assistant = msg
                    except Exception:
                        continue

            if is_pure_search_session(
                total_user_turns,
                has_non_search_user_turn,
                title=clean_text_snippet(first_user, 32) if first_user else "",
                last_assistant=last_assistant
            ):
                continue

            is_target = target_ws and is_matching_workspace(target_ws, actual_cwd)
            mod_dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

            title = f"Codex: {clean_text_snippet(first_user, 32)}" if first_user else f"Codex 会话 ({session_id[:8]})"
            all_user_text = "\n".join(user_prompts_labeled)
            deep_content = f"{all_user_text}\n{extract_deep_transcript_content(filepath)}".strip() if deep_scan else all_user_text

            results.append({
                "agent": "codex",
                "session_id": session_id,
                "resume_command": get_resume_command("codex", session_id),
                "title": title,
                "workspace": actual_cwd or "未知目录",
                "last_modified": mod_dt,
                "is_current_workspace": bool(is_target),
                "transcript_path": filepath,
                "last_user_turn": last_user,
                "last_assistant_turn": last_assistant,
                "deep_content": deep_content
            })
        except Exception:
            continue
    return results

# ==============================================================================
# 5. 全量扫描总分发入口
# ==============================================================================
def scan_all_agents(
    target_workspace: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    agent_filter: Optional[str] = None,
    deep_scan: bool = False
) -> List[Dict[str, Any]]:
    """扫描指定时间范围内的全部智能体会话"""
    all_sessions = []
    agent_filter_clean = agent_filter.lower().strip() if agent_filter else None

    scanners = [
        ("antigravity", scan_antigravity_sessions),
        ("claude", scan_claude_sessions),
        ("omp", scan_omp_sessions),
        ("pi", scan_pi_sessions),
        ("codex", scan_codex_sessions),
    ]

    for name, scanner_fn in scanners:
        if agent_filter_clean and agent_filter_clean != name:
            continue
        try:
            sessions = scanner_fn(target_workspace, start_dt, end_dt, deep_scan=deep_scan)
            all_sessions.extend(sessions)
        except Exception:
            continue

    # 按修改时间降序排序
    all_sessions.sort(key=lambda s: s.get("last_modified", ""), reverse=True)
    return all_sessions
