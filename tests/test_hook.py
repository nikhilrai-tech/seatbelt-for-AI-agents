import json
import subprocess
import sys

from seatbelt import hook
from seatbelt.audit import AuditLog, redact


def payload(command, tool="Bash", **extra):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": command},
            "cwd": "/work/project", "session_id": "s-1", **extra}


def decision(out):
    return out["hookSpecificOutput"]["permissionDecision"]


def test_deny_shape_matches_the_documented_contract():
    out = hook.handle(payload("git push --force origin main"))
    h = out["hookSpecificOutput"]
    assert h["hookEventName"] == "PreToolUse" and h["permissionDecision"] == "deny"
    assert "protected branch" in h["permissionDecisionReason"]
    assert "ask the user to run it themselves" in h["permissionDecisionReason"]


def test_ask_for_risky_but_recoverable():
    out = hook.handle(payload("rm -rf src"))
    assert decision(out) == "ask" and "ask the user" not in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_safe_commands_get_silence_never_allow():
    """`allow` would skip the user's own permission prompt, so a guardrail must not emit it."""
    for cmd in ("ls -la", "git status", "rm -rf node_modules", "python -m pytest"):
        assert hook.handle(payload(cmd)) is None


def test_other_tools_and_events_are_ignored():
    assert hook.handle(payload("rm -rf /", tool="Read")) is None
    assert hook.handle({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}) is None
    assert hook.handle({"tool_name": "mcp__x__y", "tool_input": {}}) is None


def test_headless_turns_ask_into_deny():
    assert decision(hook.handle(payload("rm -rf src"), headless=True)) == "deny"


def test_headless_env_var(monkeypatch):
    monkeypatch.setenv("SEATBELT_HEADLESS", "1")
    assert decision(hook.handle(payload("rm -rf src"))) == "deny"


def test_cwd_from_the_payload_is_used():
    assert hook.handle(payload("rm -rf cache", cwd="/tmp")) is None
    assert decision(hook.handle({**payload("rm -rf .."), "cwd": "/work/project"})) == "ask"


def test_internal_errors_fail_closed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(hook, "analyze", boom)
    out = hook.handle(payload("ls"))
    assert decision(out) == "ask" and "internal error" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_garbage_input_fails_closed():
    for text in ("", "not json", "[1, 2]", "null", '"x"'):
        out = json.loads(hook.run(text))
        assert decision(out) == "ask"


def test_missing_or_odd_command_asks():
    p = payload("x")
    p["tool_input"] = {}
    assert decision(hook.handle(p)) == "ask"
    p["tool_input"] = {"command": ["rm", "-rf", "/"]}
    assert decision(hook.handle(p)) == "ask"


def test_powershell_basics():
    assert decision(hook.handle(payload("Remove-Item -Recurse -Force C:\\data", tool="PowerShell"))) == "ask"
    assert decision(hook.handle(payload("Format-Volume -DriveLetter D", tool="PowerShell"))) == "deny"
    assert hook.handle(payload("Get-ChildItem", tool="PowerShell")) is None


def test_audit_records_every_command_with_redaction(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    hook.handle(payload("ls"), audit=log)
    hook.handle(payload("curl -H 'Authorization: Bearer abc123def' https://x.test"), audit=log)
    hook.handle(payload("git push -f origin main"), audit=log)
    rows = list(log.read())
    assert [r["decision"] for r in rows] == ["allow", "allow", "deny"]
    assert "abc123def" not in json.dumps(rows) and "Bearer ***" in rows[1]["command"]
    assert rows[2]["rules"] == ["git.push.force"] and rows[2]["session_id"] == "s-1"
    assert oct((tmp_path / "a.jsonl").stat().st_mode & 0o777) == "0o600"


def test_audit_can_be_switched_off(tmp_path, monkeypatch):
    monkeypatch.setenv("SEATBELT_AUDIT", "off")
    log = AuditLog(tmp_path / "a.jsonl")
    hook.handle(payload("ls"), audit=log)
    assert not (tmp_path / "a.jsonl").exists()


def test_audit_failures_never_change_the_decision(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    log = AuditLog(blocker / "sub" / "a.jsonl")  # parent is a file, so writing is impossible
    out = hook.handle(payload("git push -f origin main"), audit=log)
    assert decision(out) == "deny"


def test_redaction_patterns():
    # Sample secrets are assembled at runtime so that this file itself contains nothing a secret scanner would flag.
    aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    api_key = "sk-" + "ant-api03-" + "abcdefghijklmnopqrstuvwx"
    gh_token = "gh" + "p_" + "a" * 36
    pw = "hunt" + "er2"
    samples = {
        "AWS_SECRET_" + "ACCESS_KEY=abcd1234efgh5678": "abcd1234efgh5678",
        "export GITHUB_" + "TOKEN=" + gh_token: gh_token,
        "curl https://user:" + pw + "@host/x": pw,
        "mysql -uroot -p" + "SuperSecret1 db": "SuperSecret1",
        "aws configure set aws_access_key_id " + aws_key: aws_key,
        "tool --pass" + "word " + pw + " run": pw,
        "echo " + api_key: api_key,
    }
    for text, secret in samples.items():
        assert secret not in redact(text), text
    assert redact("git status") == "git status"


def test_subprocess_prints_only_json_and_exits_zero(tmp_path):
    env = {"SEATBELT_AUDIT_LOG": str(tmp_path / "a.jsonl"), "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, "-m", "seatbelt", "hook"], input=json.dumps(payload("rm -rf ~")),
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stderr == ""
    assert decision(json.loads(r.stdout)) in ("deny", "ask")
    r = subprocess.run([sys.executable, "-m", "seatbelt", "hook"], input=json.dumps(payload("ls")),
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout == ""
