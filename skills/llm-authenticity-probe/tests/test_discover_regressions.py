"""发现层的回归测试：评审中暴露的边界行为。

与 test_discover.py 的区别：这里只钉「曾经错过的」行为，防止回退。
"""
import json
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import probe  # noqa: E402

SCHEMA = ("CREATE TABLE model_cache (provider_id TEXT PRIMARY KEY, "
          "version INTEGER, materialization_policy TEXT, updated_at INTEGER, "
          "authoritative INTEGER, static_fingerprint TEXT, "
          "header_omitted_model_ids TEXT, unrestorable_header_model_ids TEXT, "
          "header_restore_version INTEGER, models TEXT, models_hash TEXT)")


@pytest.fixture
def omp_db(tmp_path):
    """在 tmp home 里建一个可写 models.db，返回插入函数。"""
    os.makedirs(tmp_path / ".omp" / "agent", exist_ok=True)
    db = sqlite3.connect(str(tmp_path / ".omp" / "agent" / "models.db"))
    db.execute(SCHEMA)
    db.commit()

    def add(provider_id, models):
        db.execute("INSERT INTO model_cache VALUES "
                   "(?,0,'',0,0,'','[]','[]',0,?,'')",
                   (provider_id, json.dumps(models)))
        db.commit()

    yield add
    db.close()


def test_unknown_api_is_marked_untestable_not_guessed(omp_db, tmp_path):
    """非 messages/chat-completions 的 api 必须标不可测，不能按模型名猜。"""
    omp_db("p", [{"id": "gpt-5.6-luna", "api": "openai-responses",
                  "baseUrl": "http://h/v1"}])
    t = probe.discover_endpoints(home=str(tmp_path))[0]
    assert "不可测" in t["untestable"]
    assert probe._testable(t) is False


def test_known_apis_remain_testable(omp_db, tmp_path):
    omp_db("p", [
        {"id": "claude-opus-5-5", "api": "anthropic-messages",
         "baseUrl": "http://h/v1"},
        {"id": "gpt-5.6-sol", "api": "openai-completions",
         "baseUrl": "http://h/v1"},
    ])
    ts = probe.discover_endpoints(home=str(tmp_path))
    assert {t["model"]: t["proto"] for t in ts} == {
        "claude-opus-5-5": "anthropic", "gpt-5.6-sol": "openai"}
    assert all(probe._testable(t) for t in ts)


def test_missing_default_config_does_not_abort_discovery(omp_db, tmp_path):
    """默认 opencode 路径不存在是常态，不能中断其余三源的发现。"""
    omp_db("p", [{"id": "claude-opus-5-5", "api": "anthropic-messages",
                  "baseUrl": "http://h/v1"}])
    ts = probe.discover_endpoints(home=str(tmp_path))
    assert [t["model"] for t in ts] == ["claude-opus-5-5"]


def test_explicit_config_that_is_missing_is_an_error(tmp_path):
    """用户显式 --config 写错路径必须报错，而不是静默返回空。"""
    with pytest.raises(SystemExit):
        probe.discover_endpoints(home=str(tmp_path),
                                 config=str(tmp_path / "nope.json"))


def test_resolve_endpoint_finds_non_target_family_so_gate_can_report(tmp_path):
    """非目标家族要能被定位到，好让 main 的家族门禁给出「测不了」。"""
    os.makedirs(tmp_path / ".config" / "opencode", exist_ok=True)
    (tmp_path / ".config" / "opencode" / "opencode.json").write_text(json.dumps({
        "provider": {"g": {"npm": "@ai-sdk/google",
                           "options": {"baseURL": "http://h", "apiKey": "k"},
                           "models": {"gemini-3-flash": {}}}}
    }), encoding="utf-8")
    t = probe.resolve_endpoint("g", "gemini-3-flash",
                               str(tmp_path / ".config/opencode/opencode.json"))
    assert t["model"] == "gemini-3-flash"
