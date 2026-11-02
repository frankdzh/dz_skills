import unittest
import tempfile
import sqlite3
import json
import os
import shutil
import datetime
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from agent_scanner import (
    scan_antigravity_sessions_from_dir,
    scan_claude_sessions_from_dir,
    scan_workbuddy_sessions_from_dir,
    scan_workbuddy_sessions,
    get_resume_command
)

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
            json.dumps(["file:///Users/example/proj1"]),
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
            json.dumps(["file:///Users/example/proj1"]),
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
            f.write(json.dumps({"type": "cwd", "cwd": "/Users/example/proj1"}) + "\n")
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
            json.dumps(["file:///Users/example/proj1"]),
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
            f.write(json.dumps({"type": "cwd", "cwd": "/Users/example/proj2"}) + "\n")
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

    def _make_workbuddy_session(self, base_dir, project_dir, session_id, cwd, title, user_text, assistant_text):
        proj = os.path.join(base_dir, "projects", project_dir)
        os.makedirs(proj, exist_ok=True)
        path = os.path.join(proj, f"{session_id}.jsonl")

        def user_line(text):
            wrapped = (
                '<system-reminder data-role="user-context">\n'
                "<user_info>OS: darwin</user_info>\n"
                "</system-reminder>\n"
                f"<user_query>{text}</user_query>"
            )
            return json.dumps({
                "type": "message", "role": "user", "sessionId": session_id, "cwd": cwd,
                "content": [{"type": "input_text", "text": wrapped}]
            }, ensure_ascii=False) + "\n"

        with open(path, "w", encoding="utf-8") as f:
            f.write(user_line(user_text))
            f.write(json.dumps({
                "type": "ai-title", "sessionId": session_id, "cwd": cwd, "aiTitle": title
            }, ensure_ascii=False) + "\n")
            f.write(json.dumps({
                "type": "function_call", "name": "Bash", "arguments": {"command": "pytest -q"},
                "sessionId": session_id, "cwd": cwd
            }, ensure_ascii=False) + "\n")
            f.write(json.dumps({
                "type": "message", "role": "assistant", "sessionId": session_id, "cwd": cwd,
                "content": [{"type": "output_text", "text": assistant_text}]
            }, ensure_ascii=False) + "\n")
        return path

    def test_scan_workbuddy_session_fields(self):
        cwd = "/Users/example/proj-wb"
        path = self._make_workbuddy_session(
            self.test_dir, "example-proj-wb", "wb-sess-1", cwd,
            "重构支付回调", "帮我重构支付回调签名", "已完成签名重构"
        )
        target_mtime = (self.now - datetime.timedelta(days=1)).timestamp()
        os.utime(path, (target_mtime, target_mtime))

        results = scan_workbuddy_sessions_from_dir(
            self.test_dir, cwd, self.start_dt, self.end_dt, deep_scan=True
        )
        self.assertEqual(len(results), 1)
        s = results[0]
        self.assertEqual(s["agent"], "workbuddy")
        self.assertEqual(s["session_id"], "wb-sess-1")
        self.assertEqual(s["title"], "WorkBuddy: 重构支付回调")
        self.assertEqual(s["workspace"], cwd)
        self.assertTrue(s["is_current_workspace"])
        self.assertEqual(s["last_user_turn"], "帮我重构支付回调签名")
        self.assertEqual(s["last_assistant_turn"], "已完成签名重构")
        self.assertIsNone(s["resume_command"])
        # 环境包装不得计入，真实正文只出现一次
        self.assertNotIn("system-reminder", s["deep_content"])
        self.assertEqual(s["deep_content"].count("帮我重构支付回调签名"), 1)
        # --deep 应穿透到工具调用
        self.assertIn("pytest -q", s["deep_content"])

    def test_scan_workbuddy_excludes_pure_search_session(self):
        path = self._make_workbuddy_session(
            self.test_dir, "example-search", "wb-search", "/Users/example/search",
            "检索历史会话", "/dz-transcript-search 查一下支付回调", "### 🔍 会话日志模糊与语义检索看板"
        )
        target_mtime = (self.now - datetime.timedelta(days=1)).timestamp()
        os.utime(path, (target_mtime, target_mtime))

        results = scan_workbuddy_sessions_from_dir(
            self.test_dir, "", self.start_dt, self.end_dt, deep_scan=False
        )
        self.assertEqual(len(results), 0, "纯检索技能调用会话必须被排除")

    def test_scan_workbuddy_plain_user_message(self):
        # 旧版或非包装格式：没有 <user_query> 时仍按普通正文处理
        cwd = "/Users/example/plain"
        proj = os.path.join(self.test_dir, "projects", "example-plain")
        os.makedirs(proj, exist_ok=True)
        path = os.path.join(proj, "wb-plain.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "type": "message", "role": "user", "sessionId": "wb-plain", "cwd": cwd,
                "content": [{"type": "input_text", "text": "直接给出的需求"}]
            }, ensure_ascii=False) + "\n")
            f.write(json.dumps({
                "type": "message", "role": "assistant", "sessionId": "wb-plain", "cwd": cwd,
                "content": [{"type": "output_text", "text": "直接给出的答复"}]
            }, ensure_ascii=False) + "\n")
        target_mtime = (self.now - datetime.timedelta(days=1)).timestamp()
        os.utime(path, (target_mtime, target_mtime))

        results = scan_workbuddy_sessions_from_dir(
            self.test_dir, "", self.start_dt, self.end_dt, deep_scan=False
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["last_user_turn"], "直接给出的需求")

    def test_scan_workbuddy_time_filtering(self):
        old_path = self._make_workbuddy_session(
            self.test_dir, "example-old", "wb-old", "/Users/example/old",
            "旧会话", "过旧的提问", "过旧的答复"
        )
        old_mtime = (self.now - datetime.timedelta(days=10)).timestamp()
        os.utime(old_path, (old_mtime, old_mtime))

        results = scan_workbuddy_sessions_from_dir(
            self.test_dir, "", self.start_dt, self.end_dt, deep_scan=False
        )
        self.assertEqual(len(results), 0)

    def test_scan_workbuddy_covers_cn_and_intl_dirs(self):
        cn_path = self._make_workbuddy_session(
            os.path.join(self.test_dir, ".workbuddy"), "p-cn", "wb-cn",
            "/Users/example/cn", "国内版会话", "国内版提问", "国内版答复"
        )
        intl_path = self._make_workbuddy_session(
            os.path.join(self.test_dir, ".workbuddy-ai"), "p-intl", "wb-intl",
            "/Users/example/intl", "国际版会话", "国际版提问", "国际版答复"
        )
        target_mtime = (self.now - datetime.timedelta(days=1)).timestamp()
        for p in (cn_path, intl_path):
            os.utime(p, (target_mtime, target_mtime))

        with patch("agent_scanner.os.path.expanduser", return_value=self.test_dir):
            results = scan_workbuddy_sessions("", self.start_dt, self.end_dt)
        ids = {r["session_id"] for r in results}
        self.assertEqual(ids, {"wb-cn", "wb-intl"})

if __name__ == "__main__":
    unittest.main()
