"""发现层 seam 测试：discover_endpoints(home) 把本机各 agent 配置
归一成统一 target 列表。

只测公共行为：给定 home 下的配置文件，返回哪些端点、带什么协议与凭据来源。
不测内部解析细节。
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import probe  # noqa: E402

SCHEMA = ("CREATE TABLE model_cache (provider_id TEXT PRIMARY KEY, "
          "version INTEGER, materialization_policy TEXT, updated_at INTEGER, "
          "authoritative INTEGER, static_fingerprint TEXT, "
          "header_omitted_model_ids TEXT, unrestorable_header_model_ids TEXT, "
          "header_restore_version INTEGER, models TEXT, models_hash TEXT)")


def _omp_db(home, provider_id, models):
    """建一个最小 models.db，写入一条 provider 记录。"""
    os.makedirs(f"{home}/.omp/agent", exist_ok=True)
    db = sqlite3.connect(f"{home}/.omp/agent/models.db")
    db.execute(SCHEMA)
    db.execute("INSERT INTO model_cache VALUES (?,0,'',0,0,'','[]','[]',0,?,'')",
               (provider_id, json.dumps(models)))
    db.commit()
    db.close()


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _targets(home):
    return {f"{t['provider']}/{t['model']}": t
            for t in probe.discover_endpoints(home=home)}


def test_opencode_provider_yields_targets_with_inline_key(tmp_path):
    home = str(tmp_path)
    _write(f"{home}/.config/opencode/opencode.json", json.dumps({
        "provider": {
            "relay-b": {
                "npm": "@ai-sdk/anthropic",
                "options": {"baseURL": "http://127.0.0.1:9998/v1",
                            "apiKey": "sk-inline"},
                "models": {"claude-opus-4-6": {"name": "Opus"}},
            }
        }
    }))
    t = _targets(home)["relay-b/claude-opus-4-6"]
    assert t["baseURL"] == "http://127.0.0.1:9998/v1"
    assert t["apiKey"] == "sk-inline"
    assert t["proto"] == "anthropic"
    assert t["source"] == "opencode"


def test_omp_models_db_yields_targets_with_proto_from_api_field(tmp_path):
    home = str(tmp_path)
    _omp_db(home, "relay-a", [
        {"id": "zp/claude-opus-5.5", "api": "anthropic-messages",
         "provider": "relay-a", "baseUrl": "http://127.0.0.1:9999"},
        {"id": "zp/glm-5.3", "api": "openai-completions",
         "provider": "relay-a", "baseUrl": "http://127.0.0.1:9999"},
    ])

    ts = _targets(home)
    claude = ts["relay-a/zp/claude-opus-5.5"]
    assert claude["proto"] == "anthropic"
    assert claude["baseURL"] == "http://127.0.0.1:9999"
    assert claude["source"] == "omp"
    # 非目标家族（glm）默认不出现在列表里
    assert "relay-a/zp/glm-5.3" not in ts


def test_omp_key_comes_from_provider_env_var(tmp_path, monkeypatch):
    home = str(tmp_path)
    _omp_db(home, "relay-a", [
        {"id": "claude-opus-5-5", "api": "anthropic-messages",
         "baseUrl": "http://127.0.0.1:9999"}])
    monkeypatch.setenv("RELAY_A_API_KEY", "sk-from-env")

    t = _targets(home)["relay-a/claude-opus-5-5"]
    assert t["apiKeyEnv"] == "RELAY_A_API_KEY"
    assert t["apiKey"] == "sk-from-env"


def test_claude_settings_yields_single_endpoint_with_any_model(tmp_path):
    home = str(tmp_path)
    _write(f"{home}/.claude/settings.json", json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:9997",
                "ANTHROPIC_AUTH_TOKEN": "tok-123"},
        "modelPicker": {"options": [{"model": "unorouter/gpt-6-luna"}]}
    }))
    t = _targets(home)["claude-code/claude-opus-5-5"]
    assert t["baseURL"] == "http://127.0.0.1:9997"
    assert t["apiKey"] == "tok-123"
    assert t["proto"] == "anthropic"
    assert t["any_model"] is True
    assert t["source"] == "claude"

    luna = _targets(home)["claude-code/unorouter/gpt-6-luna"]
    assert luna["baseURL"] == "http://127.0.0.1:9997"
    assert luna["proto"] == "openai"


def test_codex_responses_wire_api_is_marked_untestable(tmp_path):
    home = str(tmp_path)
    _write(f"{home}/.codex/config.toml", """
model_providers.custom]
""".replace("model_providers.custom]", "[model_providers.custom]") + """
name = "relay-a"
base_url = "http://127.0.0.1:9999/v1"
wire_api = "responses"
experimental_bearer_token = "tok"
model = "gpt-5.6-sol"
""")
    t = _targets(home)["custom/gpt-5.6-sol"]
    assert t["proto"] == "openai"
    assert "responses" in t["untestable"]   # 不可测原因：wire_api 不兼容
    assert t["apiKey"] == "tok"


def test_non_target_families_are_filtered_by_default(tmp_path):
    home = str(tmp_path)
    _write(f"{home}/.config/opencode/opencode.json", json.dumps({
        "provider": {"g": {"npm": "@ai-sdk/google",
                           "options": {"baseURL": "http://h", "apiKey": "k"},
                           "models": {"gemini-3-flash": {}}}}
    }))
    assert probe.discover_endpoints(home=home) == []
    all_ts = probe.discover_endpoints(home=home, include_other=True)
    assert len(all_ts) == 1


def test_same_endpoint_from_two_sources_is_deduped(tmp_path):
    home = str(tmp_path)
    body = {"provider": {"a": {"npm": "@ai-sdk/anthropic",
                               "options": {"baseURL": "http://127.0.0.1:9999/v1",
                                           "apiKey": "k"},
                               "models": {"claude-opus-5-5": {}}}}}
    _write(f"{home}/.config/opencode/opencode.json", json.dumps(body))
    _omp_db(home, "a", json.dumps([{"id": "claude-opus-5-5",
                                  "api": "anthropic-messages",
                                  "baseUrl": "http://127.0.0.1:9999/v1"}]))

    ts = probe.discover_endpoints(home=home)
    assert len(ts) == 1


def test_missing_sources_yield_empty_list(tmp_path):
    assert probe.discover_endpoints(home=str(tmp_path)) == []


# ── 跨平台配置兼容 ────────────────────────────────────────────────


def test_bom_prefixed_json_is_read(tmp_path):
    """Windows/VS Code 保存的 JSON 常带 BOM，不能因此丢掉整个源。"""
    home = str(tmp_path)
    os.makedirs(f"{home}/.claude", exist_ok=True)
    with open(f"{home}/.claude/settings.json", "wb") as f:
        f.write(b"\xef\xbb\xbf" + json.dumps({
            "env": {"ANTHROPIC_BASE_URL": "http://h",
                    "ANTHROPIC_AUTH_TOKEN": "tok"}}).encode())
    ts = probe.discover_endpoints(home=home)
    assert [t["provider"] for t in ts] == ["claude-code"]


def test_claude_settings_local_overrides_base_settings(tmp_path):
    """Claude Code 会合并 settings.local.json，且后者优先。"""
    home = str(tmp_path)
    os.makedirs(f"{home}/.claude", exist_ok=True)
    with open(f"{home}/.claude/settings.json", "w", encoding="utf-8") as f:
        json.dump({"model": "claude-opus-5-5",
                   "env": {"ANTHROPIC_BASE_URL": "http://base",
                           "ANTHROPIC_AUTH_TOKEN": "base-tok"}}, f)
    with open(f"{home}/.claude/settings.local.json", "w", encoding="utf-8") as f:
        json.dump({"env": {"ANTHROPIC_BASE_URL": "http://local"}}, f)
    t = probe.discover_endpoints(home=home)[0]
    assert t["baseURL"] == "http://local"     # 端点被覆盖
    assert t["apiKey"] == "base-tok"          # 未覆盖的键保留


def test_bom_prefixed_opencode_json_is_read(tmp_path):
    home = str(tmp_path)
    _write(f"{home}/.config/opencode/opencode.json", "")
    with open(f"{home}/.config/opencode/opencode.json", "wb") as f:
        f.write(b"\xef\xbb\xbf" + json.dumps({
            "provider": {"p": {"npm": "@ai-sdk/anthropic",
                               "options": {"baseURL": "http://h", "apiKey": "k"},
                               "models": {"claude-opus-5-5": {}}}}}).encode())
    assert [t["provider"] for t in probe.discover_endpoints(home=home)] == ["p"]
