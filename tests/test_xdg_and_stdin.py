import io
from pathlib import Path

from seatbelt import doctor, hook
from seatbelt import policy as policy_mod
from seatbelt.cli import main
from seatbelt.context import Context
from seatbelt.engine import analyze
from seatbelt.model import Level

HOME = "/home/dev"
CTX = ["--no-config", "--cwd", "/work/project", "--home", HOME]


# ---------------------------------------------------------------- XDG_CONFIG_HOME (issue #15)

def test_config_dir_follows_the_xdg_spec():
    assert policy_mod.config_dir(HOME, {}) == Path("/home/dev/.config/seatbelt")
    assert policy_mod.config_dir(HOME, {"XDG_CONFIG_HOME": "/etc/xdg-me"}) == Path("/etc/xdg-me/seatbelt")
    assert policy_mod.config_dir(HOME, {"XDG_CONFIG_HOME": "relative/path"}) == Path("/home/dev/.config/seatbelt")  # spec: ignore non-absolute
    assert policy_mod.config_dir(HOME, {"XDG_CONFIG_HOME": ""}) == Path("/home/dev/.config/seatbelt")


def test_seatbelt_config_still_wins_over_xdg():
    env = {"XDG_CONFIG_HOME": "/xdg", "SEATBELT_CONFIG": "/explicit/c.toml"}
    assert policy_mod.user_config_path(HOME, env) == Path("/explicit/c.toml")
    assert policy_mod.user_config_path(HOME, {"XDG_CONFIG_HOME": "/xdg"}) == Path("/xdg/seatbelt/config.toml")


def test_the_config_is_really_read_from_xdg(tmp_path):
    xdg = tmp_path / "xdg"
    (xdg / "seatbelt").mkdir(parents=True)
    (xdg / "seatbelt" / "config.toml").write_text('[[deny]]\ncommand = "echo nope"\nreason = "from xdg"\n')
    p = policy_mod.load(str(tmp_path), str(tmp_path / "home"), {"XDG_CONFIG_HOME": str(xdg)})
    assert [r.reason for r in p.deny] == ["from xdg"] and p.error is None


def test_an_agent_cannot_edit_the_config_in_the_xdg_location(tmp_path):
    """The tamper protection has to move with the config, or the guardrail could be edited by the agent."""
    ctx = Context(cwd="/work/project", home=HOME, environ={"XDG_CONFIG_HOME": "/xdg"})
    assert analyze("echo '[[allow]]' >> /xdg/seatbelt/config.toml", ctx).level == Level.DENY
    assert analyze("rm /xdg/seatbelt/config.toml", ctx).level == Level.DENY
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": "/work/project",
               "tool_input": {"file_path": "/xdg/seatbelt/config.toml", "content": "x"}}
    import os
    old = os.environ.get("XDG_CONFIG_HOME")
    os.environ["XDG_CONFIG_HOME"] = "/xdg"
    try:
        assert hook.handle(payload)["hookSpecificOutput"]["permissionDecision"] == "deny"
    finally:
        os.environ.pop("XDG_CONFIG_HOME") if old is None else os.environ.update(XDG_CONFIG_HOME=old)
    # the default location stays protected too, and unrelated files under XDG are not
    assert analyze("rm ~/.config/seatbelt/config.toml", Context(cwd="/work/project", home=HOME, environ={})).level == Level.DENY
    assert analyze("touch /xdg/other/file.txt", ctx).level == Level.ALLOW


def test_the_explicit_seatbelt_config_file_is_protected_too():
    ctx = Context(cwd="/work/project", home=HOME, environ={"SEATBELT_CONFIG": "/somewhere/my-seatbelt.toml"})
    assert analyze("echo x > /somewhere/my-seatbelt.toml", ctx).level == Level.DENY


def test_doctor_says_where_the_config_would_be(tmp_path):
    checks = doctor.run(str(tmp_path), str(tmp_path), {"XDG_CONFIG_HOME": "/xdg"}, lambda c, p: (0, "", ""), lambda: (2, 1, 302), {})
    cfg = next(c for c in checks if c.title == "configuration")
    assert "/xdg/seatbelt/config.toml" in cfg.detail


# ---------------------------------------------------------------- check --stdin (issue #16)

def feed(monkeypatch, text):
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_stdin_mode_checks_every_line_and_summarises(monkeypatch, capsys):
    feed(monkeypatch, "git status\nrm -rf src\ngit push --force origin main\nls\n")
    assert main(["check", "--stdin", "--no-color", *CTX]) == 0
    out = capsys.readouterr().out
    assert "ALLOW git status" in out and "ASK   rm -rf src" in out and "DENY  git push --force origin main" in out
    assert "4 commands: 2 left alone, 1 would ask first, 1 would be denied." in out
    assert "false positive" in out


def test_quiet_hides_the_commands_that_are_left_alone(monkeypatch, capsys):
    feed(monkeypatch, "git status\nrm -rf src\nls\n")
    assert main(["check", "--stdin", "--quiet", "--no-color", *CTX]) == 0
    out = capsys.readouterr().out
    assert "git status" not in out and "rm -rf src" in out and "3 commands: 2 left alone" in out


def test_history_formats_comments_and_blank_lines(monkeypatch, capsys):
    feed(monkeypatch, "#1700000000\ngit status\n: 1700000000:0;git push -f origin main\n\n   \n# note\n")
    assert main(["check", "--stdin", "--no-color", *CTX]) == 0
    out = capsys.readouterr().out
    assert "2 commands" in out and "DENY  git push -f origin main" in out  # the zsh prefix is stripped


def test_stdin_output_is_redacted_so_it_is_safe_to_paste(monkeypatch, capsys):
    secret = "gh" + "p_" + "a" * 36
    feed(monkeypatch, f"export GITHUB_TOKEN={secret}\ncurl -H 'Authorization: Bearer abcdef123456' https://x.test\n")
    main(["check", "--stdin", "--no-color", *CTX])
    out = capsys.readouterr().out
    assert secret not in out and "abcdef123456" not in out and "***" in out


def test_stdin_mode_never_walks_the_disk_for_previews(monkeypatch, capsys, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x")
    feed(monkeypatch, "rm -rf src\n")
    main(["check", "--stdin", "--no-color", "--no-config", "--cwd", str(tmp_path), "--home", HOME])
    assert "impact" not in capsys.readouterr().out


def test_empty_stdin_is_an_error_not_a_crash(monkeypatch, capsys):
    feed(monkeypatch, "\n# only a comment\n")
    assert main(["check", "--stdin", *CTX]) == 2
    assert "no commands on stdin" in capsys.readouterr().err


def test_a_big_history_is_fast(monkeypatch, capsys):
    import time
    feed(monkeypatch, "\n".join(["git status", "npm test", "rm -rf node_modules", "kubectl get pods", "ls -la"] * 400))
    start = time.monotonic()
    assert main(["check", "--stdin", "--quiet", "--no-color", *CTX]) == 0
    assert time.monotonic() - start < 8
    assert "2000 commands: 2000 left alone" in capsys.readouterr().out
