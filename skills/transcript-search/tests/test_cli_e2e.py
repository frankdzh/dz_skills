import unittest
import subprocess
import json
import sys
import os

SCRIPT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "search_agent_logs.py"))

class TestCliE2E(unittest.TestCase):
    def test_help_flag(self):
        res = subprocess.run([sys.executable, SCRIPT_PATH, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("search_agent_logs.py", res.stdout)
        self.assertIn("--since", res.stdout)
        self.assertIn("--deep", res.stdout)
        self.assertIn("--compact", res.stdout)

    def test_compact_flag(self):
        res = subprocess.run([sys.executable, SCRIPT_PATH, "--since", "1d", "--compact"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("紧凑模式", res.stdout)
        self.assertIn("[⚡ 引擎耗时:", res.stdout)
        self.assertIn("[🕒 检索跨度:", res.stdout)

    def test_dashboard_badges(self):
        res = subprocess.run([sys.executable, SCRIPT_PATH, "--since", "1d"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("[⚡ 引擎耗时:", res.stdout)
        self.assertIn("[🕒 检索跨度:", res.stdout)
        self.assertIn("[📊 命中:", res.stdout)

    def test_total_elapsed_flag(self):
        res = subprocess.run([sys.executable, SCRIPT_PATH, "--since", "1d", "--total-elapsed", "12.5"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("[⚡ 交互时延: 12.5s (引擎:", res.stdout)

    def test_json_flag(self):
        # 搜索一个词，带 --json
        res = subprocess.run([sys.executable, SCRIPT_PATH, "test_dummy_query", "--since", "1d", "--json", "--total-elapsed", "5.0"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        try:
            data = json.loads(res.stdout)
            self.assertIn("query", data)
            self.assertIn("total_matches", data)
            self.assertIn("engine_elapsed_seconds", data)
            self.assertEqual(data.get("total_elapsed_seconds"), 5.0)
            self.assertIn("auto_expanded", data)
            self.assertIn("results", data)
        except Exception as e:
            self.fail(f"Output is not valid JSON: {res.stdout}\nError: {e}")

if __name__ == "__main__":
    unittest.main()
