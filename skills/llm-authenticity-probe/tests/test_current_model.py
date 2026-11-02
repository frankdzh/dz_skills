"""当前会话模型的端点定位：--current。

数据源是 omp 的 agent.db → model_usage（按 last_used_at 排序取最新），
model_key 形如 agent-role/opencode-go/deepseek-v4.1-flash：首段是 omp 的
模型角色 provider，其余段是上游 provider + 模型名。
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import probe  # noqa: E402

USAGE_SCHEMA = ("CREATE TABLE model_usage (model_key TEXT PRIMARY KEY, "
                "last_used_at INTEGER NOT NULL)")


def _agent_db(home, keys):
    os.makedirs(f"{home}/.omp/agent", exist_ok=True)
    db = sqlite3.connect(f"{home}/.omp/agent/agent.db")
    db.execute(USAGE_SCHEMA)
    for i, key in enumerate(keys):
        db.execute("INSERT INTO model_usage VALUES (?, ?)", (key, 1000 + i))
    db.commit()
    db.close()


def _oc(home, providers):
    path = f"{home}/.config/opencode/opencode.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"provider": providers}, f)


def test_reads_latest_model_key(tmp_path):
    _agent_db(str(tmp_path), ["agent-role/a/old-model", "agent-role/b/new-model"])
    assert probe.current_model_key(home=str(tmp_path)) == "agent-role/b/new-model"


def test_missing_agent_db_returns_none(tmp_path):
    assert probe.current_model_key(home=str(tmp_path)) is None


def test_resolves_current_model_to_endpoint(tmp_path):
    home = str(tmp_path)
    _agent_db(home, ["agent-role/up/claude-opus-5-5"])
    _oc(home, {"up": {"npm": "@ai-sdk/anthropic",
                      "options": {"baseURL": "http://h", "apiKey": "k"},
                      "models": {"claude-opus-5-5": {}}}})
    t = probe.find_current_endpoint(home=home)
    assert t["model"] == "claude-opus-5-5"
    assert t["baseURL"] == "http://h"


def test_returns_none_when_current_model_is_not_configured(tmp_path):
    home = str(tmp_path)
    _agent_db(home, ["agent-role/up/claude-opus-5-5"])
    assert probe.find_current_endpoint(home=home) is None


def test_key_env_drops_cache_suffix_then_uses_verified_alias():
    """先试去缓存后缀的名字，再按显式别名表补真名。"""
    cands = probe._key_env_candidates("opencode-go:models-v3:23272i4kkpstg")
    assert cands[:2] == ["OPENCODE_GO_MODELS_V3_23272I4KKPSTG_API_KEY",
                         "OPENCODE_GO_API_KEY"]
    assert cands[-1] == "OPENCODE_API_KEY"     # 显式核实过的别名


def test_zen_provider_never_borrows_go_key():
    """opencode-zen 没有核实过的别名，绝不能落到 OPENCODE_API_KEY。"""
    cands = probe._key_env_candidates("opencode-zen:models-v3:1s0ek0lf6mx9w")
    assert "OPENCODE_API_KEY" not in cands


def test_target_key_uses_declared_env_only(monkeypatch):
    """只认 target 自己声明的候选，不按名字猜别的 provider。"""
    t = {"apiKey": "", "apiKeyEnv": "ZEN_KEY_API_KEY",
         "envAliases": ["ZEN_KEY_API_KEY"]}
    monkeypatch.setenv("OPENCODE_API_KEY", "sk-other-provider")
    assert probe._target_key(t) == ""
    monkeypatch.setenv("ZEN_KEY_API_KEY", "sk-correct")
    assert probe._target_key(t) == "sk-correct"


# ── Claude Code 环境（无 omp agent.db）──────────────────────────────
# 异地机器上只装了 Claude Code，--current 必须从 settings.json 取模型，
# 而不是直接报「未找到 agent.db」。


def test_current_endpoint_falls_back_to_claude_settings(tmp_path):
    home = str(tmp_path)
    os.makedirs(f"{home}/.claude", exist_ok=True)
    with open(f"{home}/.claude/settings.json", "w", encoding="utf-8") as f:
        json.dump({"model": "claude-opus-5-5",
                   "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:9997",
                           "ANTHROPIC_AUTH_TOKEN": "tok-claude"}}, f)
    t = probe.find_current_endpoint(home=home)
    assert t is not None
    assert t["model"] == "claude-opus-5-5"
    assert t["baseURL"] == "http://127.0.0.1:9997"
    assert probe._target_key(t) == "tok-claude"


def test_claude_settings_model_source_is_reported(tmp_path):
    home = str(tmp_path)
    os.makedirs(f"{home}/.claude", exist_ok=True)
    with open(f"{home}/.claude/settings.json", "w", encoding="utf-8") as f:
        json.dump({"model": "u/claude-haiku-5-5[1m]",
                   "env": {"ANTHROPIC_BASE_URL": "http://h"}}, f)
    model, source = probe.current_model_info(home=home)
    assert model == "u/claude-haiku-5-5[1m]"
    assert source == "claude"


def test_omp_takes_priority_over_claude_settings(tmp_path):
    home = str(tmp_path)
    _agent_db(home, ["agent-role/up/claude-opus-5-5"])
    _oc(home, {"up": {"npm": "@ai-sdk/anthropic",
                      "options": {"baseURL": "http://h-omp", "apiKey": "k"},
                      "models": {"claude-opus-5-5": {}}}})
    os.makedirs(f"{home}/.claude", exist_ok=True)
    with open(f"{home}/.claude/settings.json", "w", encoding="utf-8") as f:
        json.dump({"model": "claude-haiku-5-5",
                   "env": {"ANTHROPIC_BASE_URL": "http://h-claude"}}, f)
    t = probe.find_current_endpoint(home=home)
    assert t["baseURL"] == "http://h-omp"


def test_no_source_at_all_returns_none(tmp_path):
    assert probe.find_current_endpoint(home=str(tmp_path)) is None
    assert probe.current_model_info(home=str(tmp_path)) == (None, None)


# ── 其他 code agent 环境（opencode / codex）──────────────────────────


def test_current_model_from_opencode_config(tmp_path):
    home = str(tmp_path)
    os.makedirs(f"{home}/.config/opencode", exist_ok=True)
    with open(f"{home}/.config/opencode/opencode.json", "w", encoding="utf-8") as f:
        json.dump({"model": "up/claude-opus-5-5",
                   "provider": {"up": {"npm": "@ai-sdk/anthropic",
                                       "options": {"baseURL": "http://h",
                                                   "apiKey": "k"},
                                       "models": {"claude-opus-5-5": {}}}}}, f)
    model, source = probe.current_model_info(home=home)
    assert (model, source) == ("up/claude-opus-5-5", "opencode")
    t = probe.find_current_endpoint(home=home)
    assert t["baseURL"] == "http://h"


def test_current_model_from_codex_config(tmp_path):
    home = str(tmp_path)
    os.makedirs(f"{home}/.codex", exist_ok=True)
    with open(f"{home}/.codex/config.toml", "w", encoding="utf-8") as f:
        f.write('model = "claude-opus-5-5"\n'
                '[model_providers.p]\n'
                'base_url = "http://h/v1"\n'
                'wire_api = "chat"\n')
    model, source = probe.current_model_info(home=home)
    assert (model, source) == ("claude-opus-5-5", "codex")


def test_claude_wins_over_opencode_when_both_present(tmp_path):
    home = str(tmp_path)
    os.makedirs(f"{home}/.claude", exist_ok=True)
    with open(f"{home}/.claude/settings.json", "w", encoding="utf-8") as f:
        json.dump({"model": "claude-haiku-5-5",
                   "env": {"ANTHROPIC_BASE_URL": "http://h"}}, f)
    os.makedirs(f"{home}/.config/opencode", exist_ok=True)
    with open(f"{home}/.config/opencode/opencode.json", "w", encoding="utf-8") as f:
        json.dump({"model": "up/claude-opus-5-5"}, f)
    assert probe.current_model_info(home=home)[1] == "claude"


def test_codex_current_endpoint_uses_model_provider(tmp_path):
    home = str(tmp_path)
    os.makedirs(f"{home}/.codex", exist_ok=True)
    with open(f"{home}/.codex/config.toml", "w", encoding="utf-8") as f:
        f.write('model = "claude-opus-5-5"\n'
                'model_provider = "relay"\n'
                '[model_providers.relay]\n'
                'base_url = "http://h/v1"\n'
                'wire_api = "chat"\n'
                'experimental_bearer_token = "tok"\n')
    t = probe.find_current_endpoint(home=home)
    assert t["baseURL"] == "http://h/v1"
    assert t["model"] == "claude-opus-5-5"
    assert probe._target_key(t) == "tok"


def test_codex_wire_api_chat_uses_openai_probe_surface(tmp_path):
    """wire_api=chat 必须走 chat/completions，而不是按模型名拼 messages。"""
    home = str(tmp_path)
    os.makedirs(f"{home}/.codex", exist_ok=True)
    with open(f"{home}/.codex/config.toml", "w", encoding="utf-8") as f:
        f.write('model = "claude-opus-5-5"\n'
                'model_provider = "relay"\n'
                '[model_providers.relay]\n'
                'base_url = "http://h/v1"\n'
                'wire_api = "chat"\n')
    t = probe.find_current_endpoint(home=home)
    assert probe._target_url(t).endswith("/v1/chat/completions")
