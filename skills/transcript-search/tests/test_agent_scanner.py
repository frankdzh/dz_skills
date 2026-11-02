import unittest
import tempfile
import sqlite3
import json
import os
import shutil
import datetime
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from agent_scanner import scan_antigravity_sessions_from_dir, scan_claude_sessions_from_dir, get_resume_command

class TestAgentScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.now = datetime.datetime(2026, 10, 22, 12, 0, 0)
        self.start_dt = self.now - datetime.timedelta(days=2)
        self.end_dt = self.now

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scan_antigravity_time_filtering(self):
        db_path = os.path.join(self.test_dir, "conversation_summaries.db")
        brain_dir = os.path.join(self.test_dir, "brain")
        os.makedirs(brain_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE conversation_summaries (
            conversation_id TEXT PRIMARY KEY,
            title TEXT,
            preview TEXT,
            last_modified_time TIMESTAMP,
            workspace_uris TEXT,
            step_count INTEGER
        )
        """)
        # 1 条在时间窗口内 (2026-10-21)
        cur.execute("""
        INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "cid-in-window",
            "测试窗口内会话",
            "会话摘要",
            "2026-10-21 15:30:00",
            json.dumps(["file:///Users/test/proj1"]),
            5
        ))
        # 1 条在时间窗口外 (2026-10-10)
        cur.execute("""
        INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "cid-old",
            "过旧的会话",
            "旧摘要",
            "2026-10-10 10:00:00",
            json.dumps(["file:///Users/test/proj1"]),
            5
        ))
        conn.commit()
        conn.close()

        # 创建 transcript.jsonl
        log_dir = os.path.join(brain_dir, "cid-in-window", ".system_generated", "logs")
        os.makedirs(log_dir, exist_ok=True)
        t_path = os.path.join(log_dir, "transcript.jsonl")
        with open(t_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "USER_INPUT", "source": "USER", "content": "<USER_REQUEST>测试用户输入</USER_REQUEST>"}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "source": "MODEL", "content": "测试助手回复，执行工具调用"}) + "\n")

        results = scan_antigravity_sessions_from_dir(db_path, brain_dir, "", self.start_dt, self.end_dt, deep_scan=True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["session_id"], "cid-in-window")
        self.assertEqual(results[0]["resume_command"], "agy --conversation cid-in-window")
        self.assertIn("测试用户输入", results[0]["last_user_turn"])
        self.assertIn("测试助手回复", results[0]["deep_content"])

    def test_scan_claude_time_filtering(self):
        claude_dir = os.path.join(self.test_dir, "projects", "proj1")
        os.makedirs(claude_dir, exist_ok=True)
        session_file = os.path.join(claude_dir, "sess-claude-1.jsonl")

        with open(session_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "cwd", "cwd": "/Users/test/proj1"}) + "\n")
            f.write(json.dumps({"type": "user", "message": {"content": "测试 Claude 用户指令"}}) + "\n")
            f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "测试 Claude 回答"}]}}) + "\n")

        # 将 mtime 设置在时间窗口内 (1天前)
        target_mtime = (self.now - datetime.timedelta(days=1)).timestamp()
        os.utime(session_file, (target_mtime, target_mtime))

        results = scan_claude_sessions_from_dir(self.test_dir, "", self.start_dt, self.end_dt, deep_scan=True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["session_id"], "sess-claude-1")
        self.assertEqual(results[0]["resume_command"], "claude --resume sess-claude-1")
        self.assertIn("测试 Claude 用户指令", results[0]["last_user_turn"])

    def test_pure_search_session_is_excluded(self):
        # 纯检索技能会话应被完全丢弃，不污染索引
        db_path = os.path.join(self.test_dir, "search_test.db")
        brain_dir = os.path.join(self.test_dir, "search_brain")
        os.makedirs(brain_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE conversation_summaries (
            conversation_id TEXT PRIMARY KEY,
            title TEXT,
            preview TEXT,
            last_modified_time TIMESTAMP,
            workspace_uris TEXT,
            step_count INTEGER
        )
        """)
        cur.execute("""
        INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "cid-pure-search",
            "Feishu Bot Message Progress Tracking",
            "/transcript-search 飞书机器人消息动态反馈进度",
            "2026-10-21 15:30:00",
            json.dumps(["file:///Users/test/proj1"]),
            5
        ))
        conn.commit()
        conn.close()

        log_dir = os.path.join(brain_dir, "cid-pure-search", ".system_generated", "logs")
        os.makedirs(log_dir, exist_ok=True)
        t_path = os.path.join(log_dir, "transcript.jsonl")
        with open(t_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "USER_INPUT", "source": "USER", "content": "<USER_REQUEST>/transcript-search 飞书机器人消息动态反馈进度</USER_REQUEST>"}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "source": "MODEL", "content": "### 🔍 会话日志模糊与语义检索看板\n> 🎯 检索词: 飞书机器人"}) + "\n")

        results = scan_antigravity_sessions_from_dir(db_path, brain_dir, "", self.start_dt, self.end_dt, deep_scan=True)
        self.assertEqual(len(results), 0, "纯检索技能调用会话必须被完全排除")

    def test_mixed_session_strips_search_turn_and_preserves_work(self):
        # 混合会话应保留正常业务提问，剥离中途调用的检索技能指令
        claude_dir = os.path.join(self.test_dir, "projects", "proj2")
        os.makedirs(claude_dir, exist_ok=True)
        session_file = os.path.join(claude_dir, "sess-mixed.jsonl")

        with open(session_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "cwd", "cwd": "/Users/test/proj2"}) + "\n")
            f.write(json.dumps({"type": "user", "message": {"content": "编写飞书网关 webhook 处理代码"}}) + "\n")
            f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "已实现飞书网关处理函数"}]}}) + "\n")
            # 中途调用检索技能
            f.write(json.dumps({"type": "user", "message": {"content": "/dz-transcript-search 某个不相干的词"}}) + "\n")
            f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "### 🔍 会话日志模糊与语义检索看板"}]}}) + "\n")

        target_mtime = (self.now - datetime.timedelta(days=1)).timestamp()
        os.utime(session_file, (target_mtime, target_mtime))

        results = scan_claude_sessions_from_dir(self.test_dir, "", self.start_dt, self.end_dt, deep_scan=True)
        self.assertEqual(len(results), 1)
        # 验证检索指令被过滤，保留真实的最后用户提问与助手产出
        self.assertEqual(results[0]["last_user_turn"], "编写飞书网关 webhook 处理代码")
        self.assertEqual(results[0]["last_assistant_turn"], "已实现飞书网关处理函数")
        self.assertNotIn("/dz-transcript-search", results[0]["deep_content"])

    def test_get_resume_command_all_agents(self):
        self.assertEqual(get_resume_command("claude", "s123"), "claude --resume s123")
        self.assertEqual(get_resume_command("codex", "s123"), "codex resume s123")
        self.assertEqual(get_resume_command("antigravity", "s123"), "agy --conversation s123")
        self.assertEqual(get_resume_command("omp", "s123"), "omp --resume s123")
        self.assertEqual(get_resume_command("pi", "s123"), "pi --resume s123")
        self.assertIsNone(get_resume_command("unknown", "s123"))

if __name__ == "__main__":
    unittest.main()
