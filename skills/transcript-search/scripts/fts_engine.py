#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基于 SQLite 内存虚拟表 FTS5 的高性能倒排检索引擎

- 零外部依赖，使用 Python 标准库 sqlite3。
- CJK 字符分词增强：自动为中文字符建立 unigram 倒排，兼顾英文分词。
- 安全查询转义：自动剥离/转义 FTS5 语法保留字，杜绝语法异常。
- BM25 相关度排序。
"""

import sqlite3
import re
from typing import List, Dict, Any, Optional

from query_processing import normalize_query

def cjk_spaced(text: str) -> str:
    """对中文字符间插入空格，使 FTS5 的 unicode61 分词器能够对中文任意连续子串做短语匹配"""
    if not text:
        return ""
    # 在每个汉字前后插入空格
    return re.sub(r"([\u4e00-\u9fa5])", r" \1 ", str(text))

PARTICLES_SPLIT_REGEX = re.compile(
    r"[的了在是我有和就不人都一上也很到说要去你会着看好自己这与或等被从把对而以及其该之用为给向让但因做来并且那么如果或者]+"
)

def extract_cjk_semantic_terms(text: str) -> List[str]:
    """基于常见助词/虚词断句与多尺度滑窗，零依赖提取中文核心概念词"""
    if not text:
        return []
    keywords = []
    chunks = PARTICLES_SPLIT_REGEX.split(text)
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        if len(chunk) <= 4:
            keywords.append(chunk)
        else:
            keywords.append(chunk)
            for i in range(len(chunk) - 1):
                keywords.append(chunk[i:i+2])
            for i in range(len(chunk) - 2):
                keywords.append(chunk[i:i+3])
    return list(dict.fromkeys(keywords))

def parse_query_terms(query: str):
    """解析查询词为主要短语集合与细粒度子词集合，增强中英文混合与长词召回"""
    if not query:
        return [], []

    query = normalize_query(query)
    if not query:
        return [], []
    clean = re.sub(r"[\"\'\(\)\*\:\^\{\}\[\]\~\+\-\<\>]", " ", query).strip()
    raw_terms = clean.split()
    
    main_terms = []
    sub_terms = []

    for term in raw_terms:
        # 分离连续英文/数字与中文
        en_words = re.findall(r"[a-zA-Z0-9_\.\-]+", term)
        cn_blocks = re.findall(r"[\u4e00-\u9fa5]+", term)

        for w in en_words:
            main_terms.append(f'"{w}"')
            sub_terms.append(f'"{w}"')

        for b in cn_blocks:
            sp = " ".join(cjk_spaced(b).split())
            if sp:
                main_terms.append(f'"{sp}"')
            
            # 使用助词切分与滑窗提取核心概念词
            semantic_terms = extract_cjk_semantic_terms(b)
            for st in semantic_terms:
                st_sp = " ".join(cjk_spaced(st).split())
                if st_sp:
                    sub_terms.append(f'"{st_sp}"')

    # 保序去重
    return list(dict.fromkeys(main_terms)), list(dict.fromkeys(sub_terms))

def sanitize_fts5_query(query: str) -> str:
    """将用户自由输入的查询转换为安全的 FTS5 AND 查询表达式"""
    main_terms, _ = parse_query_terms(query)
    if not main_terms:
        return ""
    return " AND ".join(main_terms)

class FtsEngine:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self._init_schema()
        self.sessions_map: Dict[str, Dict[str, Any]] = {}
        self.doc_counter = 0

    def _init_schema(self):
        cursor = self.conn.cursor()
        cursor.execute("""
        CREATE VIRTUAL TABLE sessions_fts USING fts5(
            doc_id UNINDEXED,
            title,
            workspace,
            last_user,
            last_assistant,
            deep_content,
            tokenize = 'unicode61'
        );
        """)
        self.conn.commit()

    def index_sessions(self, sessions: List[Dict[str, Any]]):
        """将一组会话结构插入 FTS5 内存倒排表中"""
        cursor = self.conn.cursor()
        for sess in sessions:
            self.doc_counter += 1
            doc_id = str(self.doc_counter)
            sess_copy = dict(sess)
            sess_copy["_doc_id"] = doc_id
            self.sessions_map[doc_id] = sess_copy

            title = cjk_spaced(sess.get("title", ""))
            workspace = sess.get("workspace", "")
            last_user = cjk_spaced(sess.get("last_user_turn", ""))
            last_assistant = cjk_spaced(sess.get("last_assistant_turn", ""))
            deep_content = cjk_spaced(sess.get("deep_content", ""))

            cursor.execute("""
            INSERT INTO sessions_fts(doc_id, title, workspace, last_user, last_assistant, deep_content)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (doc_id, title, workspace, last_user, last_assistant, deep_content))
            
        self.conn.commit()

    def search(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """执行查询，按 BM25 相关度升序排序（在 SQLite FTS5 中 bm25 负值越小越相关）"""
        if not query or not query.strip():
            return []

        main_terms, sub_terms = parse_query_terms(query)
        if not main_terms:
            return []

        cursor = self.conn.cursor()
        rows = []

        # 1. 优先尝试主短语严格 AND 查询
        and_q = " AND ".join(main_terms)
        try:
            cursor.execute("""
            SELECT doc_id, bm25(sessions_fts) as rank
            FROM sessions_fts
            WHERE sessions_fts MATCH ?
            ORDER BY rank ASC
            LIMIT ?
            """, (and_q, limit))
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            rows = []

        # 2. 若 AND 召回不足或包含多个词，补充/降级为综合 OR 查询保障召回深度
        if len(rows) < 5:
            combined_terms = list(dict.fromkeys(main_terms + sub_terms))
            if combined_terms:
                or_q = " OR ".join(combined_terms)
                try:
                    cursor.execute("""
                    SELECT doc_id, bm25(sessions_fts) as rank
                    FROM sessions_fts
                    WHERE sessions_fts MATCH ?
                    ORDER BY rank ASC
                    LIMIT ?
                    """, (or_q, limit))
                    or_rows = cursor.fetchall()
                    seen_ids = {r[0] for r in rows}
                    for doc_id, rank in or_rows:
                        if doc_id not in seen_ids:
                            rows.append((doc_id, rank))
                            seen_ids.add(doc_id)
                except sqlite3.OperationalError:
                    pass

        results = []
        for doc_id, rank in rows:
            if doc_id in self.sessions_map:
                item = dict(self.sessions_map[doc_id])
                item["_fts_rank"] = rank
                results.append(item)

        return results

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
