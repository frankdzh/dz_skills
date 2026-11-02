"""按模型名一键发现并探测：--model NAME（不配 --url/--from-config）。

自然语言「测一下 claude-haiku-5-5」对应的就是这条路径：
在本机全部配置源里找同名模型，挑有凭据且协议兼容的端点逐个探测。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import probe  # noqa: E402


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _oc(home, providers):
    _write(f"{home}/.config/opencode/opencode.json",
           json.dumps({"provider": providers}))


def test_normalizes_route_prefix_and_modifier():
    assert probe._norm_model("u/claude-haiku-5-5[1m]") == "claude-haiku-5-5"
    assert probe._norm_model("zp/claude-opus-5.5") == "claude-opus-5.5"
    assert probe._norm_model("claude-haiku-5-5") == "claude-haiku-5-5"
    assert probe._norm_model("gpt6-luna") == "gpt-6-luna"
    assert probe._norm_model("claude3.5-sonnet") == "claude-3.5-sonnet"
    assert probe._family_of("gpt6-luna") == "openai"


def test_finds_every_endpoint_offering_the_model(tmp_path):
    home = str(tmp_path)
    _oc(home, {
        "a": {"npm": "@ai-sdk/anthropic",
              "options": {"baseURL": "http://h1", "apiKey": "k1"},
              "models": {"claude-haiku-5-5": {}}},
        "b": {"npm": "@ai-sdk/anthropic",
              "options": {"baseURL": "http://h2", "apiKey": "k2"},
              "models": {"u/claude-haiku-5-5[1m]": {}}},
    })
    hits = probe.find_model_endpoints("claude-haiku-5-5", home=home)
    assert {t["baseURL"] for t in hits} == {"http://h1", "http://h2"}


def test_returns_empty_for_unknown_model(tmp_path):
    assert probe.find_model_endpoints("claude-nope-9",
                                      home=str(tmp_path)) == []


def test_non_target_family_is_not_silently_missing(tmp_path):
    """非目标家族要能被找到，好让调用方报「测不了」而不是「没找到」。"""
    home = str(tmp_path)
    _oc(home, {"g": {"npm": "@ai-sdk/google",
                     "options": {"baseURL": "http://h", "apiKey": "k"},
                     "models": {"gemini-3-flash": {}}}})
    assert probe.find_model_endpoints("gemini-3-flash", home=home) == []
    hits = probe.find_model_endpoints("gemini-3-flash", home=home,
                                      include_other=True)
    assert [t["model"] for t in hits] == ["gemini-3-flash"]


def test_prefers_credentialed_and_dedupes_same_endpoint(tmp_path):
    home = str(tmp_path)
    _oc(home, {
        "nokey": {"npm": "@ai-sdk/anthropic",
                  "options": {"baseURL": "http://h1"},
                  "models": {"claude-haiku-5-5": {}}},
        "withkey": {"npm": "@ai-sdk/anthropic",
                    "options": {"baseURL": "http://h1", "apiKey": "k"},
                    "models": {"claude-haiku-5-5": {}}},
    })
    hits = probe.find_model_endpoints("claude-haiku-5-5", home=home)
    assert len(hits) == 1
    assert probe._target_key(hits[0]) == "k"


def test_any_model_endpoint_matches_unlisted_model_when_asked(tmp_path):
    """Claude Code 端点接受任意模型名：未显式列出也要能按名探测。"""
    home = str(tmp_path)
    _write(f"{home}/.claude/settings.json", json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "http://relay",
                "ANTHROPIC_AUTH_TOKEN": "tok"}}))
    hits = probe.find_model_endpoints("anthropic/claude-fable-5-1",
                                      home=home, fallback_any_model=True)
    assert len(hits) == 1
    # 必须原样发送调用方给的模型 id（中转站认的是带前缀的那个）
    assert hits[0]["model"] == "anthropic/claude-fable-5-1"
    assert hits[0]["baseURL"] == "http://relay"


def test_any_model_fallback_is_off_by_default(tmp_path):
    """默认不回落，避免 --current 之类的解析被任意端点污染。"""
    home = str(tmp_path)
    _write(f"{home}/.claude/settings.json", json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "http://relay"}}))
    assert probe.find_model_endpoints("claude-fable-5-1", home=home) == []


def test_exact_match_still_wins_over_any_model(tmp_path):
    home = str(tmp_path)
    _write(f"{home}/.claude/settings.json", json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "http://relay-any"}}))
    _oc(home, {"p": {"npm": "@ai-sdk/anthropic",
                     "options": {"baseURL": "http://exact", "apiKey": "k"},
                     "models": {"claude-fable-5-1": {}}}})
    hits = probe.find_model_endpoints("claude-fable-5-1", home=home,
                                      fallback_any_model=True)
    assert [t["baseURL"] for t in hits] == ["http://exact"]
