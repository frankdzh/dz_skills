#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""灵活时间范围解析模块 (Time Window Parser)

支持自然语言相对时间 (today, yesterday, 3d, 7d, 30d, this-week 等)
以及绝对时间 (2026-10-15, 2026-10-15..2026-10-20, 2026-10-15 14:00 等)。
非法输入时优雅回退至默认 7 天并输出说明。
"""

import datetime
import re
from typing import Optional, Tuple

def get_current_time() -> datetime.datetime:
    """获取当前本地时间，便于单测 mock"""
    return datetime.datetime.now()

def parse_single_datetime(s: str, is_end_of_day: bool = False) -> Optional[datetime.datetime]:
    """尝试解析单条时间字符串"""
    if not s:
        return None
    s = s.strip()
    
    # 支持 YYYY-MM-DD HH:MM:SS
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            if fmt == "%Y-%m-%d" and is_end_of_day:
                return dt.replace(hour=23, minute=59, second=59)
            return dt
        except ValueError:
            pass
    return None

def parse_time_window(
    since_str: Optional[str] = None,
    until_str: Optional[str] = None,
    default_days: int = 7
) -> Tuple[datetime.datetime, datetime.datetime]:
    """解析起始与截止时间窗口。
    
    返回 (start_dt, end_dt)。
    若格式无法识别，优雅降级为 default_days (默认近7天)。
    """
    now = get_current_time()
    start_dt = None
    end_dt = None

    # 1. 优先检查 since_str 是否包含区间连接符 ".." 或 "~"
    if since_str and (".." in since_str or "~" in since_str):
        parts = re.split(r"\.\.|~", since_str, maxsplit=1)
        s_part, e_part = parts[0].strip(), parts[1].strip()
        parsed_s = parse_single_datetime(s_part, is_end_of_day=False)
        parsed_e = parse_single_datetime(e_part, is_end_of_day=True)
        if parsed_s and parsed_e:
            return parsed_s, parsed_e
        elif parsed_s:
            start_dt = parsed_s

    # 2. 解析 until_str
    if until_str:
        low_until = until_str.strip().lower()
        if low_until in ("now", "今天", "today"):
            end_dt = now
        elif low_until in ("yesterday", "昨天"):
            y_start = (now - datetime.timedelta(days=1)).replace(hour=23, minute=59, second=59)
            end_dt = y_start
        else:
            parsed = parse_single_datetime(until_str, is_end_of_day=True)
            if parsed:
                end_dt = parsed

    if not end_dt:
        end_dt = now

    # 3. 解析 since_str
    if since_str:
        s = since_str.strip().lower()
        if s in ("today", "今天"):
            start_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif s in ("yesterday", "昨天"):
            y = now - datetime.timedelta(days=1)
            start_dt = y.replace(hour=0, minute=0, second=0, microsecond=0)
        elif s in ("this-week", "本周"):
            start_dt = (now - datetime.timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            # 尝试相对天数/小时如 3d, 7d, 24h, 30m
            m = re.match(r"^(\d+)\s*([dhw])$", s)
            if m:
                val = int(m.group(1))
                unit = m.group(2)
                if unit == "d":
                    start_dt = now - datetime.timedelta(days=val)
                elif unit == "h":
                    start_dt = now - datetime.timedelta(hours=val)
                elif unit == "w":
                    start_dt = now - datetime.timedelta(weeks=val)
            else:
                parsed = parse_single_datetime(since_str, is_end_of_day=False)
                if parsed:
                    start_dt = parsed

    # 4. 兜底策略：若未能成功解析 start_dt，回退至 default_days
    if not start_dt:
        start_dt = now - datetime.timedelta(days=default_days)

    # 保证 start_dt <= end_dt
    if start_dt > end_dt:
        start_dt, end_dt = end_dt, start_dt

    return start_dt, end_dt

def extract_time_intent_and_clean_query(
    query: str, default_since: str = "7d"
) -> Tuple[str, Optional[str], Optional[str]]:
    """从自然语言查询中智能提炼时间意图与核心关键词。

    例如: "昨天有一个讨论pi定制智能体编排任务的会话"
    -> cleaned: "pi 定制智能体 编排任务", detected_since: "yesterday", detected_until: "today"
    """
    if not query:
        return "", None, None

    q = query.strip()
    detected_since = None
    detected_until = None

    # 1. 匹配并提取相对时间词（注意中文不具备 ASCII \b 词边界）
    time_patterns = [
        (r"(?i)(?:\byesterday\b|昨天|昨日)", "yesterday", "today"),
        (r"(?i)(?:\bthe day before yesterday\b|前天)", "2d", "yesterday"),
        (r"(?i)(?:\btoday\b|今天|今日)", "today", "now"),
        (r"(?i)(?:近|过去)\s*(\d+)\s*天", lambda m: f"{m.group(1)}d", "now"),
        (r"(?i)(?:\blast week\b|上周|过去一周)", "7d", "now"),
    ]

    for pat, s_val, u_val in time_patterns:
        m = re.search(pat, q)
        if m:
            detected_since = s_val(m) if callable(s_val) else s_val
            detected_until = u_val(m) if callable(u_val) else u_val
            # 抹除该时间短语
            q = q[:m.start()] + " " + q[m.end():]
            break

    # 2. 剥离纯会话包装词与助词
    stop_phrases = [
        r"有一个", r"有一条", r"有哪[些个]", r"有没有",
        r"帮我[搜查找]一下", r"[搜查找]一下", r"关于", r"相关的?",
        r"讨论", r"聊过", r"的会话", r"的对话", r"的记录", r"的内容"
    ]
    for sp in stop_phrases:
        q = re.sub(sp, " ", q)

    # 3. 提取英文/数字词与中文词块
    en_words = re.findall(r"[a-zA-Z0-9_\.\-]+", q)
    cn_blocks = re.findall(r"[\u4e00-\u9fa5]+", q)

    tokens = []
    tokens.extend(en_words)
    tokens.extend(cn_blocks)

    cleaned_q = " ".join([t for t in tokens if t.strip()])
    return cleaned_q or q.strip(), detected_since, detected_until

def format_time_window_desc(start_dt: datetime.datetime, end_dt: datetime.datetime) -> str:
    """生成易于人类阅读的时间区间说明"""
    s_str = start_dt.strftime("%Y-%m-%d %H:%M")
    e_str = end_dt.strftime("%Y-%m-%d %H:%M")
    delta_days = (end_dt - start_dt).total_seconds() / 86400.0
    if abs(delta_days - round(delta_days)) < 0.1:
        d_label = f"近{int(round(delta_days))}天"
    else:
        d_label = f"跨度约{delta_days:.1f}天"
    return f"{s_str} ~ {e_str} ({d_label})"

def format_compact_span(start_dt: datetime.datetime, end_dt: datetime.datetime) -> str:
    """生成紧凑的时间跨度标签，如 32h, 1.3天, 7天"""
    total_seconds = max(0.0, (end_dt - start_dt).total_seconds())
    total_hours = total_seconds / 3600.0
    if total_hours < 48:
        if total_hours == int(total_hours):
            return f"{int(total_hours)}h"
        return f"{total_hours:.1f}h"
    days = total_hours / 24.0
    if abs(days - round(days)) < 0.1:
        return f"{int(round(days))}天"
    return f"{days:.1f}天"

