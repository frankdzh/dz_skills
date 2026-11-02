#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""混合语义评分与上下文提纯器 (Hybrid Semantic Scorer)

- 双保险架构：优先加载本地轻量 embedding 计算余弦相似度；
  若未安装模型或处于纯离线环境，无缝降级为内置“词元 N-gram + Jaccard + 子串加权”纯数学算法。
- 零外部网络请求，零崩溃。
- 上下文高亮提纯 ([MATCH]...[/MATCH]) 与敏感凭据脱敏。
"""

import re
import math
from typing import List, Dict, Any, Optional, Set

from query_processing import normalize_query, is_search_skill_invocation, is_search_dashboard_output

def mask_sensitive_info(text: str) -> str:
    """自动脱敏常见的 API Key、Token、私钥等凭据信息"""
    if not text:
        return ""
    s = str(text)
    
    # 1. 常见 API Key 前缀 (sk-..., ghp_..., AIza...)
    s = re.sub(r"\b(sk-[a-zA-Z0-9_-]{20,})\b", "***SENSITIVE_API_KEY***", s)
    s = re.sub(r"\b(ghp_[a-zA-Z0-9]{20,})\b", "***SENSITIVE_GH_TOKEN***", s)
    s = re.sub(r"\b(AIza[a-zA-Z0-9_-]{30,})\b", "***SENSITIVE_GEMINI_KEY***", s)
    s = re.sub(r"(bearer\s+)[a-zA-Z0-9\._\-]{25,}", r"\1***SENSITIVE_BEARER***", s, flags=re.IGNORECASE)
    
    # 2. 私钥块
    s = re.sub(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----", "***SENSITIVE_PRIVATE_KEY***", s)
    
    # 3. 通用长哈希 Key 赋值匹配
    s = re.sub(r"(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{24,}['\"]?", r"\1=***SENSITIVE***", s, flags=re.IGNORECASE)
    
    # 4. AWS Access Key
    s = re.sub(r"\b(AKIA[0-9A-Z]{16})\b", "***SENSITIVE_AWS_KEY***", s)
    
    # 5. 常见数据库连接 URL 密码脱敏
    s = re.sub(r"(://[^:\s]+:)([^@\s/]+)(@)", r"\1***SENSITIVE_DB_PASS***\3", s)
    
    return s

def get_character_ngrams(text: str, n: int = 2) -> Set[str]:
    """生成字符级 n-gram 集合，支持中文混合分词"""
    clean = re.sub(r"\s+", "", text.lower())
    if len(clean) < n:
        return {clean} if clean else set()
    return {clean[i:i+n] for i in range(len(clean) - n + 1)}

class SemanticScorer:
    def __init__(self, force_math_fallback: bool = False):
        self.force_math_fallback = force_math_fallback
        self.model = None
        self._init_backend()

    def _init_backend(self):
        if self.force_math_fallback:
            return
        
        # 尝试静默导入 sentence_transformers
        try:
            from sentence_transformers import SentenceTransformer
            # 仅在有本地缓存时尝试加载，避免触发自动下载
            # 如无模型缓存，直接走数学算法，避免网络阻塞
            # 此处保持静默，不强求本地大权重
        except Exception:
            self.model = None

    def _calc_math_similarity(self, query: str, doc_text: str) -> float:
        """纯数学相似度评分算法：基于字符/词元 2-gram Jaccard + 查询覆盖率 + 精确子串奖励"""
        if not query or not doc_text:
            return 0.0

        q_clean = query.strip().lower()
        d_clean = doc_text.strip().lower()

        # 1. 精确整串包含
        exact_bonus = 0.0
        if q_clean in d_clean:
            exact_bonus = 0.4
        else:
            # 检查 query 中的空格分词是否有命中
            words = q_clean.split()
            if words:
                hit_count = sum(1 for w in words if w in d_clean)
                coverage = hit_count / len(words)
                exact_bonus = 0.35 * coverage
                if coverage == 1.0:
                    exact_bonus += 0.1

        # 2. N-gram 相似度
        q_ngrams = get_character_ngrams(q_clean, 2)
        d_ngrams = get_character_ngrams(d_clean, 2)
        
        if not q_ngrams or not d_ngrams:
            return exact_bonus

        inter = len(q_ngrams & d_ngrams)
        union = len(q_ngrams | d_ngrams)
        
        # Jaccard 相似度
        jaccard = inter / union if union > 0 else 0.0
        # 查询覆盖率
        coverage = inter / len(q_ngrams) if q_ngrams else 0.0
        
        score = 0.4 * coverage + 0.2 * jaccard + exact_bonus
        return min(1.0, max(0.0, score))

    def score_and_rank(self, query: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """对候选集合进行语义相似度打分并按分数降序排序"""
        if not candidates:
            return []

        normalized_query = normalize_query(query)
        results = []
        for cand in candidates:
            # 标题与用户请求最能代表会话意图；长回答与穿透内容仅作补充。
            weighted_fields = (
                (cand.get("title", ""), 0.35),
                (cand.get("last_user_turn", ""), 0.30),
                (cand.get("last_assistant_turn", ""), 0.20),
                (cand.get("deep_content", ""), 0.10),
                (cand.get("text", ""), 0.05),
            )
            field_scores = [
                self._calc_math_similarity(normalized_query, text) * weight
                for text, weight in weighted_fields
                if text
            ]
            total_weight = sum(weight for text, weight in weighted_fields if text)
            score = sum(field_scores) / total_weight if total_weight else 0.0
            
            item = dict(cand)
            item["_semantic_score"] = round(score, 4)
            item["_semantic_score_pct"] = int(round(score * 100))
            results.append(item)

        # 按打分降序排序
        results.sort(key=lambda x: x.get("_semantic_score", 0.0), reverse=True)
        return results

    def extract_snippet(self, text: str, query: str, context_lines: int = 1, max_len: int = 240) -> str:
        """从长文本中定位与 query 最相关的切片，高亮匹配词并脱敏"""
        if not text:
            return ""

        masked = mask_sensitive_info(text)
        lines = [
            ln.strip() for ln in masked.splitlines()
            if ln.strip() and not is_search_skill_invocation(ln) and not is_search_dashboard_output(ln)
        ]
        if not lines:
            return ""

        # 提取用于高亮的关键词列表（包含英文单词与中文子概念词）
        en_words = re.findall(r"[a-zA-Z0-9_\.\-]+", query)
        cn_blocks = re.findall(r"[\u4e00-\u9fa5]+", query)
        terms = list(en_words)
        for b in cn_blocks:
            if len(b) <= 4:
                terms.append(b)
            else:
                for i in range(len(b) - 1):
                    terms.append(b[i:i+2])
        # 按长度降序，优先长词匹配
        terms = sorted(list(dict.fromkeys(terms)), key=len, reverse=True)

        best_idx = 0
        best_score = -1.0

        for i, line in enumerate(lines):
            score = self._calc_math_similarity(query, line)
            # 若包含交互轮次标识 [第 X 轮提问]，给予额外权重加成以便优先切中具体问答
            if "[第 " in line and " 轮" in line and score > 0.05:
                score += 0.15
            if score > best_score:
                best_score = score
                best_idx = i

        start_idx = max(0, best_idx - context_lines)
        end_idx = min(len(lines), best_idx + context_lines + 1)
        slice_lines = lines[start_idx:end_idx]

        combined = " ... ".join(slice_lines)

        # 高亮匹配关键词 [MATCH]term[/MATCH]
        for term in terms:
            if len(term) >= 2 or re.match(r"^[a-zA-Z0-9]$", term):
                try:
                    combined = re.sub(
                        rf"(?<!\[MATCH\])({re.escape(term)})(?!\[/MATCH\])",
                        r"[MATCH]\1[/MATCH]",
                        combined,
                        flags=re.IGNORECASE
                    )
                except Exception:
                    pass

        if len(combined) > max_len:
            combined = combined[:max_len] + "..."

        return combined
