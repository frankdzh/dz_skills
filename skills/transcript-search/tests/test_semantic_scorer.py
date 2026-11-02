import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from semantic_scorer import SemanticScorer, mask_sensitive_info

class TestSemanticScorer(unittest.TestCase):
    def setUp(self):
        # 强制在无本地权重时使用数学语义降级算法测试
        self.scorer = SemanticScorer(force_math_fallback=True)

    def test_math_similarity_ranking(self):
        query = "微信支付回调验签"
        candidates = [
            {"session_id": "c1", "text": "讨论周末去哪里聚餐吃饭"},
            {"session_id": "c2", "text": "微信支付 webhook 签名验证失败排查"},
            {"session_id": "c3", "text": "数据库 SQL 慢查询优化"}
        ]
        ranked = self.scorer.score_and_rank(query, candidates)
        self.assertEqual(len(ranked), 3)
        # 匹配度最高的应该排在第一位 (c2)
        self.assertEqual(ranked[0]["session_id"], "c2")
        self.assertGreater(ranked[0]["_semantic_score"], ranked[1]["_semantic_score"])

    def test_title_and_user_fields_outrank_long_irrelevant_text(self):
        target = {
            "session_id": "target",
            "title": "Chrome用户丢失排查",
            "last_user_turn": "好像用户又丢失了，检查一下原因",
            "last_assistant_turn": "彻底退出异常 Chrome 进程后，冷启动可恢复 7 个用户配置。",
        }
        noise = {
            "session_id": "noise",
            "title": "Oracle 免费机保活守护",
            "last_user_turn": "讨论 CPU 保活策略",
            "last_assistant_turn": "这里出现了用户以及问题等泛化词语，但主体内容与 Chrome 丢失无关。",
        }
        ranked = self.scorer.score_and_rank("chrome 丢失 用户", [noise, target])
        self.assertEqual(ranked[0]["session_id"], "target")
        self.assertGreaterEqual(ranked[0]["_semantic_score_pct"], 60)

    def test_extract_snippet_with_match_highlight(self):
        text = """第一行环境初始化
第二行加载配置文件
第三行排查微信支付回调验签失败的问题，定位到换行符缺失
第四行单测通过
第五行准备集成测试"""
        snippet = self.scorer.extract_snippet(text, "微信支付回调")
        self.assertIn("[MATCH]", snippet)
        self.assertIn("[/MATCH]", snippet)
        self.assertIn("验签失败", snippet)

    def test_sensitive_masking(self):
        raw_text = "API_KEY=sk-TESTFAKE0000000000000000 正在请求接口"
        masked = mask_sensitive_info(raw_text)
        self.assertNotIn("sk-TESTFAKE0000000000000000", masked)
        self.assertIn("***SENSITIVE", masked)

        # 测试 AWS 与 DB URL 密码脱敏
        db_text = "连接串 postgres://admin:TESTFAKEPASS@192.0.2.1:5432/mydb 正在连库，key=AKIAQTESTFAKEKEY0000"
        db_masked = mask_sensitive_info(db_text)
        self.assertNotIn("TESTFAKEPASS", db_masked)
        self.assertNotIn("AKIAQTESTFAKEKEY0000", db_masked)
        self.assertIn("***SENSITIVE_DB_PASS***", db_masked)
        self.assertIn("***SENSITIVE_AWS_KEY***", db_masked)

if __name__ == "__main__":
    unittest.main()
