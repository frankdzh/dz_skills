#!/usr/bin/env python3
"""veridrop 兼容层：修上游渲染 bug 后调用其 CLI。

上游 e87ed92 在 OpenAI/GPT 协议的 `protocol` 检测里，把 `issues` 产出为
dict 列表（`protocol_templates.py:153`），而 `Report._note_for` 直接
`", ".join(issues[:2])` —— 于是渲染阶段抛 TypeError，并且因为
`render_terminal` 在 `write_json` **之前**执行，JSON 报告压根写不出来。

本层只修渲染，不改任何判定逻辑：
1. `_note_for` 遇到 dict 元素时压平成可读字符串；
2. `render_terminal` 再包一层兜底，渲染失败也保证 JSON 落盘。

用法与 `relay-detector` 完全一致，由 delegate.py 用它替代原入口。
"""
import sys

from relay_detector.report import Report

_PREVIEW_KEYS = ("code", "name", "message", "detail", "reason", "field", "path")


def _flatten(item):
    """把 issues 元素压平成一行的字符串。"""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in _PREVIEW_KEYS:
            val = item.get(key)
            if val:
                return str(val)
        return ", ".join(f"{k}={v}" for k, v in list(item.items())[:2])
    return str(item)


_orig_note_for = Report._note_for


def _safe_note_for(self, r):
    try:
        return _orig_note_for(self, r)
    except TypeError:
        # 仅 protocol 分支的 ", ".join(issues) 会踩到 dict
        issues = r.details.get("issues") or []
        if not issues:
            return "[dim]协议合规[/dim]"
        flat = [_flatten(i) for i in issues]
        preview = ", ".join(flat[:2])
        more = "" if len(flat) <= 2 else f" (+{len(flat) - 2})"
        return f"[yellow]{preview}{more}[/yellow]"


Report._note_for = _safe_note_for

_orig_render = Report.render_terminal


def _safe_render(self, report):
    try:
        _orig_render(self, report)
    except Exception as e:  # noqa: BLE001 - 渲染失败不能吞掉 JSON 报告
        self.console.print(
            f"[yellow]⚠ 终端渲染异常（已跳过，JSON 仍会写出）：{e!r}[/yellow]")


Report.render_terminal = _safe_render


def main():
    from relay_detector.cli import app
    return app()


if __name__ == "__main__":
    sys.argv[0] = sys.argv[0].removesuffix(".exe")
    sys.exit(main())
