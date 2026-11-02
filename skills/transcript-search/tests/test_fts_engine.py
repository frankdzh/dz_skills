import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from fts_engine import FtsEngine
from query_processing import normalize_query

class TestFtsEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FtsEngine()
        self.sample_sessions = [
            {
                "session_id": "sess-1",
                "agent": "antigravity",
                "title": "排查微信支付回调验签失败",
                "workspace": "/Users/example/payment-service",
                "last_user_turn": "微信支付 webhook 报错 401 签名不合法",
                "last_assistant_turn": "修复了公钥换行符格式并重试验签成功",
                "deep_content": "openssl verify -CAfile cert.pem /tmp/sign.bin\nHTTP 200 OK",
                "mtime": 1729500000.0
            },
            {
                "session_id": "sess-2",
                "agent": "claude",
                "title": "重构订单状态机",
                "workspace": "/Users/example/payment-service",
                "last_user_turn": "重构订单状态变更事件与状态机",
                "last_assistant_turn": "使用 XState 模式完成了状态机重构，补齐单测",
                "deep_content": "npm test -- order-state-machine",
                "mtime": 1729400000.0
            },
            {
                "session_id": "sess-3",
                "agent": "codex",
                "title": "优化数据库查询索引",
                "workspace": "/Users/example/user-center",
                "last_user_turn": "慢 SQL 优化与索引添加",
                "last_assistant_turn": "为 users 表添加复合索引 idx_status_created_at",
                "deep_content": "EXPLAIN SELECT * FROM users WHERE status = 1",
                "mtime": 1729300000.0
            }
        ]
        self.engine.index_sessions(self.sample_sessions)

    def test_single_keyword_search(self):
        results = self.engine.search("微信支付")
        self.assertTrue(len(results) >= 1)
        self.assertEqual(results[0]["session_id"], "sess-1")

    def test_multi_keywords_search(self):
        results = self.engine.search("支付 签名")
        self.assertTrue(len(results) >= 1)
        self.assertEqual(results[0]["session_id"], "sess-1")

    def test_deep_content_search(self):
        results = self.engine.search("openssl")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["session_id"], "sess-1")

    def test_special_characters_safety(self):
        # 包含 SQLite FTS5 特殊操作符，如引号、星号、括号、冒号
        queries = ['"微信"', "status:1", "users*", "(order)", "NOT MATCH", "OR AND"]
        for q in queries:
            try:
                results = self.engine.search(q)
                self.assertIsInstance(results, list)
            except Exception as e:
                self.fail(f"Query {q} failed with exception: {e}")

    def test_no_match(self):
        results = self.engine.search("完全不存在的生僻词语xyz123")
        self.assertEqual(len(results), 0)

    def test_natural_query_removes_temporal_filler_and_splits_intent(self):
        self.assertEqual(
            normalize_query("前几天chrome丢失用户的问题"),
            "chrome 丢失 用户",
        )

if __name__ == "__main__":
    unittest.main()
