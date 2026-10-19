import json

from seatbelt import install
from seatbelt.cli import main


def entry(block=False):
    return install.build_entry("/venv/bin/seatbelt hook", block)


def test_merge_into_empty_settings():
    s, changed = install.merge({}, entry())
    assert changed
    assert s["hooks"]["PreToolUse"] == [{"matcher": "Bash|PowerShell", "hooks": [{"type": "command", "command": "/venv/bin/seatbelt hook"}]}]


def test_merge_keeps_everything_else_and_is_idempotent():
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/other-hook"}]}
    s, _ = install.merge({"model": "x", "permissions": {"allow": ["Bash(ls)"]}, "hooks": {"PreToolUse": [mine], "Stop": [1]}}, entry())
    s, changed = install.merge(s, entry())
    assert not changed
    assert s["model"] == "x" and s["permissions"] == {"allow": ["Bash(ls)"]} and s["hooks"]["Stop"] == [1]
    assert s["hooks"]["PreToolUse"][0] == mine and len(s["hooks"]["PreToolUse"]) == 2


def test_on_failure_block_flag():
    assert install.build_entry("c seatbelt hook", True)["hooks"][0]["onFailure"] == "block"
    assert "onFailure" not in install.build_entry("c seatbelt hook", False)["hooks"][0]


def test_remove_only_removes_ours():
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/other-hook"}]}
    s, _ = install.merge({"hooks": {"PreToolUse": [mine]}}, entry())
    s, changed = install.remove(s)
    assert changed and s["hooks"]["PreToolUse"] == [mine]
    s, _ = install.remove({"hooks": {"PreToolUse": [entry()]}, "model": "x"})
    assert s == {"model": "x"}
    assert install.remove({})[1] is False


def test_cli_dry_run_changes_nothing(tmp_path, capsys):
    f = tmp_path / "settings.json"
    assert main(["install", "claude-code", "--settings-file", str(f)]) == 0
    assert not f.exists() and "dry run" in capsys.readouterr().out


def test_cli_write_creates_backup_and_merges(tmp_path, capsys):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"model": "x"}))
    assert main(["install", "claude-code", "--settings-file", str(f), "--write"]) == 0
    saved = json.loads(f.read_text())
    assert saved["model"] == "x" and "seatbelt" in saved["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert json.loads((tmp_path / "settings.json.bak").read_text()) == {"model": "x"}
    assert main(["uninstall", "claude-code", "--settings-file", str(f), "--write"]) == 0
    assert json.loads(f.read_text()) == {"model": "x"}


def test_cli_refuses_to_touch_invalid_json(tmp_path, capsys):
    f = tmp_path / "settings.json"
    f.write_text("{nope")
    assert main(["install", "claude-code", "--settings-file", str(f), "--write"]) == 2
    assert f.read_text() == "{nope"


def test_log_command(tmp_path, capsys, monkeypatch):
    from seatbelt.audit import AuditLog
    log = tmp_path / "a.jsonl"
    AuditLog(log).record({"command": "rm -rf ~", "decision": "deny", "reason": "irreversible"})
    AuditLog(log).record({"command": "ls", "decision": "allow"})
    assert main(["log", "--audit-log", str(log), "--decision", "deny"]) == 0
    out = capsys.readouterr().out
    assert "DENY" in out and "rm -rf ~" in out and "ls" not in out
