#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自然语言查询提纯，降低时间状语与口语后缀对召回的影响。"""

import re
from typing import Any

_TEMPORAL_PATTERNS = re.compile(
    r"(?:这|前|上|最近)?(?:几天|几天内|两天|三天|一周|上周|本月)|今天|昨天|前天",
)
_FILLER_SUFFIX = re.compile(r"(?:的问题|问题|这个事|这件事)$")
_COMMON_CONCEPTS = re.compile(
    r"(丢失|消失|用户|登录|配置|备份|恢复|会话|日志|插件|浏览器)"
)

_SEARCH_SKILL_CMD_REGEX = re.compile(
    r"^[`\"']?/(?:skill:)?(?:dz-)?transcript[-_]?search\b",
    re.IGNORECASE
)
_SEARCH_SCRIPT_REGEX = re.compile(r"search_agent_logs\.py", re.IGNORECASE)
_SEARCH_SKILL_META_REGEX = re.compile(
    r"(?:<(?:SKILL|skill)>[\s\S]*?(?:dz-)?transcript[-_]?search[\s\S]*?</(?:SKILL|skill)>|explicitly invoked the \((?:dz-)?transcript[-_]?search\) skill)",
    re.IGNORECASE
)
_ROUND_PREFIX_REGEX = re.compile(r"^\[第\s*\d+\s*轮提问\]\s*")


def normalize_query(query: str) -> str:
    """去掉时间口头禅与后缀，保留中英文核心检索词。"""
    if not query:
        return ""
    clean = query.strip().lower()
    clean = _TEMPORAL_PATTERNS.sub(" ", clean)
    clean = _FILLER_SUFFIX.sub(" ", clean)
    clean = _COMMON_CONCEPTS.sub(r" \1 ", clean)
    clean = re.sub(r"[^\w\u4e00-\u9fa5]+", " ", clean, flags=re.UNICODE)
    return " ".join(clean.split())


def is_search_skill_invocation(text: Any) -> bool:
    """判断一段文本是否属于 transcript-search 检索技能本身的调用指令或技能元数据"""
    if not text:
        return False
    raw = str(text).strip()
    
    # 剥离 XML/系统包裹标签（如 <USER_REQUEST>...</USER_REQUEST>）
    t = raw
    if "<USER_REQUEST>" in t:
        start_tag = t.find("<USER_REQUEST>") + len("<USER_REQUEST>")
        end_tag = t.find("</USER_REQUEST>", start_tag)
        t = t[start_tag:end_tag if end_tag != -1 else None].strip()

    # 剥离交互轮次前缀（如 "[第 1 轮提问] "）
    t = _ROUND_PREFIX_REGEX.sub("", t).strip()

    # 1. 匹配斜杠指令前缀 (如 /dz-transcript-search, /transcript-search, /skill:dz-transcript-search)
    if _SEARCH_SKILL_CMD_REGEX.search(t):
        return True

    # 2. 匹配执行检索脚本的命令行
    if _SEARCH_SCRIPT_REGEX.search(t):
        return True

    # 3. 匹配注入的技能描述或元数据块
    if _SEARCH_SKILL_META_REGEX.search(raw):
        return True

    return False


def is_search_dashboard_output(text: Any) -> bool:
    """判断一段文本是否属于 transcript-search 检索技能输出的看板或结论摘要包装"""
    if not text:
        return False
    t = str(text).strip()
    if "会话日志模糊与语义检索看板" in t or "会话日志检索 (紧凑模式)" in t:
        return True
    if "### 🔍 会话日志" in t and ("检索词:" in t or "🎯" in t):
        return True
    if "🎯 检索词:" in t and "窗口明细:" in t:
        return True
    if ("[⚡ 引擎耗时:" in t or "[⚡ 交互时延:" in t or "[⚡ 总耗时:" in t) and ("检索跨度:" in t and "命中:" in t):
        return True
    if "全域检索定位到关于" in t and "会话" in t:
        return True
    return False


def is_pure_search_session(
    total_user_turns: int,
    has_non_search_user_turn: bool,
    title: str = "",
    preview: str = "",
    last_assistant: str = ""
) -> bool:
    """综合判定某个会话是否纯粹是检索技能执行会话"""
    # 1. 存在用户交互且全部用户指令均为检索指令
    if total_user_turns > 0 and not has_non_search_user_turn:
        return True
    # 2. 标题本身是检索指令或看板输出
    if is_search_skill_invocation(title) or is_search_dashboard_output(title):
        return True
    # 3. preview/last_assistant 是检索指令或看板输出，且没有非检索用户提问
    if is_search_skill_invocation(preview) or is_search_dashboard_output(preview):
        if not has_non_search_user_turn:
            return True
    if is_search_dashboard_output(last_assistant) and not has_non_search_user_turn:
        return True
    return False
