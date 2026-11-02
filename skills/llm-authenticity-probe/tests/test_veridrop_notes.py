"""veridrop 委派层的解读逻辑：区分「路由前缀差异」与「真实模型替换」。

上游 veridrop 按字面比较 response.model，中转站加路由前缀
（cx/gpt-6-luna vs gpt-6-luna）会被判 model_mismatch 并扣分。
不区分就会把前缀差异读成掺水。
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import delegate as dl  # noqa: E402


def _report(tmp_path, issues, total=88.75, verdict="passed"):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({
        "total_score": total,
        "verdict": verdict,
        "results": [{"name": "protocol",
                     "details": {"issues": issues}}],
    }), encoding="utf-8")
    return str(path)


def _mismatch(expected, actual):
    return {"severity": "major", "code": "model_mismatch",
            "path": "$.model", "expected": expected, "actual": actual}


def test_route_prefix_difference_is_not_a_replacement(tmp_path):
    path = _report(tmp_path, [_mismatch("gpt-6-luna", "cx/gpt-6-luna")])
    note = dl._explain_veridrop_report(path, "gpt-6-luna", lambda m: None)
    assert "前缀差异" in note
    assert "真实模型名不符" not in note
    assert "88.75" in note


def test_other_model_name_is_reported_as_real_mismatch(tmp_path):
    path = _report(tmp_path, [_mismatch("gpt-6-luna", "claude-sonnet-4-6")])
    note = dl._explain_veridrop_report(path, "gpt-6-luna", lambda m: None)
    assert "真实模型名不符" in note
    assert "claude-sonnet-4-6" in note
    assert "前缀差异" not in note


def test_bracketed_modifier_also_counts_as_prefix_noise(tmp_path):
    path = _report(tmp_path, [_mismatch("claude-haiku-5-5",
                                        "u/claude-haiku-5-5[1m]")])
    note = dl._explain_veridrop_report(path, "claude-haiku-5-5", lambda m: None)
    assert "前缀差异" in note


def test_unrelated_issue_codes_are_ignored(tmp_path):
    path = _report(tmp_path, [{"severity": "major", "code": "usage_shape",
                               "message": "unexpected usage keys"}])
    note = dl._explain_veridrop_report(path, "gpt-6-luna", lambda m: None)
    assert "前缀差异" not in note and "真实模型名不符" not in note


def test_missing_report_file_is_survivable(tmp_path):
    assert dl._explain_veridrop_report(str(tmp_path / "nope.json"),
                                       "x", lambda m: None) == ""


def test_strip_route_prefix():
    assert dl._strip_route_prefix("cx/gpt-6-luna") == "gpt-6-luna"
    assert dl._strip_route_prefix("u/claude-haiku-5-5[1m]") == "claude-haiku-5-5"
    assert dl._strip_route_prefix("gpt-6-luna") == "gpt-6-luna"
    assert dl._strip_route_prefix("") == ""


# ── auto 委派的提示语义 ──────────────────────────────────────────


def _suspect_report():
    import probe
    rep = probe.Report("http://h", "claude-x")
    rep.flags.add("suspect")
    rep.conclusion = "结论：模型真假无法确定"
    return rep


def test_auto_veridrop_reports_it_already_ran(monkeypatch, capsys):
    import probe
    import delegate as dl
    monkeypatch.setattr(dl, "is_installed", lambda n: True)
    ran = []
    monkeypatch.setattr(dl, "RUNNERS", {
        "veridrop": lambda t, m, **kw: ran.append(m) or (True, "")})

    class A:
        delegate = "auto"
        from_config = None

    probe.maybe_delegate(A(), "http://h/v1/messages", "k", "claude-x",
                         _suspect_report())
    out = capsys.readouterr().out
    assert ran == ["claude-x"]
    assert "已自动执行" in out


def test_delegate_none_still_shows_manual_path(monkeypatch, capsys):
    import probe

    class A:
        delegate = "none"
        from_config = None

    probe.maybe_delegate(A(), "http://h/v1/messages", "k", "claude-x",
                         _suspect_report())
    out = capsys.readouterr().out
    assert "--delegate veridrop" in out
