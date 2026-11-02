"""WorkBuddy 双版本的端点发现与当前模型选择。"""
import json
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import probe  # noqa: E402


def _models(home, entries, edition=".workbuddy", wrapped=False):
    path = os.path.join(home, edition, "models.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig") as f:
        json.dump({"models": entries} if wrapped else entries, f)


def _session_db(home, model, last_activity=2_000_000, updated_at=1_000_000,
                edition=".workbuddy", wal=False):
    path = os.path.join(home, edition, "workbuddy.db")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    if wal:
        db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE sessions (model TEXT, last_activity_at INTEGER, "
               "updated_at INTEGER, deleted_at INTEGER)")
    db.execute("INSERT INTO sessions VALUES (?, ?, ?, NULL)",
               (model, last_activity, updated_at))
    db.commit()
    db.close()
    return path


def _omp_usage(home, model, last_used_at):
    path = os.path.join(home, ".omp", "agent", "agent.db")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE model_usage (model_key TEXT PRIMARY KEY, "
               "last_used_at INTEGER)")
    db.execute("INSERT INTO model_usage VALUES (?, ?)", (model, last_used_at))
    db.commit()
    db.close()


def _entry(model="claude-haiku-5-5", url="https://wb.example/v1", **extra):
    return dict(id=model, url=url, apiKey="sk-workbuddy", **extra)


def test_discovers_bare_model_array(tmp_path):
    home = str(tmp_path)
    _models(home, [_entry()])

    t = probe.discover_endpoints(home=home)[0]
    assert t["model"] == "claude-haiku-5-5"
    assert t["baseURL"] == "https://wb.example/v1"
    assert t["apiKey"] == "sk-workbuddy"
    assert t["proto"] == "openai"
    assert t["source"] == "workbuddy"


def test_discovers_wrapped_models_and_skips_disabled(tmp_path):
    home = str(tmp_path)
    _models(home, [_entry(), _entry(model="gpt-5.6-sol", disabled=True)],
            wrapped=True)

    ts = probe.discover_endpoints(home=home)
    assert [t["model"] for t in ts] == ["claude-haiku-5-5"]


def test_discovers_international_edition(tmp_path):
    home = str(tmp_path)
    _models(home, [_entry()], edition=".workbuddy-ai")

    t = probe.discover_endpoints(home=home)[0]
    assert t["source"] == "workbuddy-ai"
    assert t["provider"] == "workbuddy-ai"


def test_messages_url_selects_anthropic_protocol(tmp_path):
    home = str(tmp_path)
    _models(home, [_entry(url="https://wb.example/v1/messages",
                          useCustomProtocol=True)])

    assert probe.discover_endpoints(home=home)[0]["proto"] == "anthropic"


def test_custom_protocol_falls_back_to_model_family(tmp_path):
    home = str(tmp_path)
    _models(home, [
        _entry(model="claude-opus-5-5", url="https://wb.example/v1",
               useCustomProtocol=True),
        _entry(model="gpt-5.6-sol", url="https://wb.example/v2",
               useCustomProtocol=True),
    ])

    by_model = {t["model"]: t["proto"]
                for t in probe.discover_endpoints(home=home)}
    assert by_model == {"claude-opus-5-5": "anthropic",
                        "gpt-5.6-sol": "openai"}


def test_current_model_resolves_custom_local_prefix_and_endpoint(tmp_path):
    home = str(tmp_path)
    _models(home, [_entry()])
    _session_db(home, "custom-local:claude-haiku-5-5")

    assert probe.current_model_info(home=home) == (
        "claude-haiku-5-5", "workbuddy")
    t = probe.find_current_endpoint(home=home)
    assert t["baseURL"] == "https://wb.example/v1"
    assert probe._target_key(t) == "sk-workbuddy"


@pytest.mark.parametrize("omp_time, expected_source", [
    (1000, "workbuddy"), (3000, "omp"),
])
def test_actual_usage_newest_timestamp_wins(tmp_path, omp_time, expected_source):
    home = str(tmp_path)
    _models(home, [_entry()])
    _session_db(home, "custom-local:claude-haiku-5-5")
    _omp_usage(home, "agent-role/up/claude-opus-5-5", omp_time)

    assert probe.current_model_info(home=home)[1] == expected_source


def test_reads_cleanly_closed_wal_database_without_shm(tmp_path):
    home = str(tmp_path)
    _models(home, [_entry()])
    db_path = _session_db(home, "custom-local:claude-haiku-5-5", wal=True)
    # WorkBuddy 干净关闭后只留下主库；去掉 SQLite 连接自动产生的侧车文件，
    # 复现普通只读连接缺少 -shm 时可能失败的现场。
    for suffix in ("-shm", "-wal"):
        if os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)
    assert not os.path.exists(db_path + "-shm")

    assert probe.current_model_info(home=home) == (
        "claude-haiku-5-5", "workbuddy")


def test_missing_workbuddy_files_add_no_targets_or_current_model(tmp_path):
    home = str(tmp_path)
    assert not [t for t in probe.discover_endpoints(home=home)
                if t["source"].startswith("workbuddy")]
    assert probe.current_model_info(home=home) == (None, None)
