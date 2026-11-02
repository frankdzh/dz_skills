import unittest
import datetime
from unittest.mock import patch
import sys
import os

# Add scripts directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from time_parser import parse_time_window, format_time_window_desc, format_compact_span

class TestTimeParser(unittest.TestCase):
    def setUp(self):
        # 固定参考时间为 2026-10-22 12:00:00
        self.fixed_now = datetime.datetime(2026, 10, 22, 12, 0, 0)

    def test_compact_span(self):
        # 测试小于48小时的小时格式
        dt1 = datetime.datetime(2026, 10, 21, 0, 0, 0)
        dt2 = datetime.datetime(2026, 10, 22, 8, 0, 0)
        span = format_compact_span(dt1, dt2)
        self.assertEqual(span, "32h")

        # 测试天数格式
        dt3 = datetime.datetime(2026, 10, 15, 12, 0, 0)
        span_7d = format_compact_span(dt3, self.fixed_now)
        self.assertEqual(span_7d, "7天")

    def test_default_window(self):
        with patch("time_parser.get_current_time", return_value=self.fixed_now):
            start_dt, end_dt = parse_time_window(None, None)
            # 默认近7天
            expected_start = self.fixed_now - datetime.timedelta(days=7)
            self.assertEqual(start_dt, expected_start)
            self.assertEqual(end_dt, self.fixed_now)

    def test_relative_days(self):
        with patch("time_parser.get_current_time", return_value=self.fixed_now):
            start_dt, end_dt = parse_time_window("3d", None)
            expected_start = self.fixed_now - datetime.timedelta(days=3)
            self.assertEqual(start_dt, expected_start)
            self.assertEqual(end_dt, self.fixed_now)

    def test_today_keyword(self):
        with patch("time_parser.get_current_time", return_value=self.fixed_now):
            start_dt, end_dt = parse_time_window("today", None)
            expected_start = datetime.datetime(2026, 10, 22, 0, 0, 0)
            self.assertEqual(start_dt, expected_start)

    def test_yesterday_keyword(self):
        with patch("time_parser.get_current_time", return_value=self.fixed_now):
            start_dt, end_dt = parse_time_window("yesterday", None)
            expected_start = datetime.datetime(2026, 10, 21, 0, 0, 0)
            self.assertEqual(start_dt, expected_start)

    def test_absolute_date_and_range(self):
        with patch("time_parser.get_current_time", return_value=self.fixed_now):
            start_dt, end_dt = parse_time_window("2026-10-15..2026-10-20", None)
            self.assertEqual(start_dt, datetime.datetime(2026, 10, 15, 0, 0, 0))
            self.assertEqual(end_dt, datetime.datetime(2026, 10, 20, 23, 59, 59))

    def test_invalid_fallback(self):
        with patch("time_parser.get_current_time", return_value=self.fixed_now):
            start_dt, end_dt = parse_time_window("invalid-time-format", None)
            # 非法时间优雅回退至默认 7 天
            expected_start = self.fixed_now - datetime.timedelta(days=7)
            self.assertEqual(start_dt, expected_start)

if __name__ == "__main__":
    unittest.main()
