import json
import sys

from seatbelt import demo, doctor, install
from seatbelt.cli import main
from seatbelt.doctor import FAIL, INFO, OK, WARN
from seatbelt.model import Level

NEW = (2, 1, 302)
OLD_CLAUDE = (2, 0, 10)


def statuses(checks):
    return {c.title: c.status for c in checks}


def settings_file(tmp_path, command="/bin/true seatbelt hook", on_failure=True, events=install.EVENTS, matcher=install.MATCHER, extra=None):
    s = {}
    for e in events:
        entry = install.build_entry(command, on_failure and e == "PreToolUse")
        entry["matcher"] = matcher
        install.merge(s, entry, e)
    s.update(extra or {})
    p = tmp_path / "settings.json"
    p.write_text(json.dumps(s))
    return p


class FakeHook:
    """Stands in for running the installed hook command."""

    def __init__(self, deny=True, safe_silent=True, code=0):
        self.deny, self.safe_silent, self.code, self.calls = deny, safe_silent, code, []

    def __call__(self, command, payload):
        self.calls.append((command, payload["tool_input"]["command"]))
        if payload["tool_input"]["command"].startswith("git push"):
            out = json.dumps({"hookSpecificOutput": {"permissionDecision": "deny" if self.deny else "ask"}})
        else:
            out = "" if self.safe_silent else '{"hookSpecificOutput": {"permissionDecision": "ask"}}'
        return self.code, out, ""


def run(tmp_path, runner=None, ver=NEW, **kw):
    path = settings_file(tmp_path, **kw)
    return doctor.run(str(tmp_path), str(tmp_path), {}, runner or FakeHook(), lambda: ver, {"user": path})


def test_a_healthy_install_has_no_problems(tmp_path):
    checks = run(tmp_path, command="/bin/true seatbelt hook")  # a stable interpreter, not a throwaway virtualenv
    assert not [c for c in checks if c.status in (FAIL, WARN)], [c for c in checks if c.status in (FAIL, WARN)]
    assert "Everything is in place" in doctor.format_checks(checks)
    assert statuses(checks)["user: a failing hook blocks (onFailure=block)"] == OK


def test_the_installed_command_is_really_run_with_a_dangerous_and_a_harmless_payload(tmp_path):
    hook = FakeHook()
    run(tmp_path, hook, command=f"{sys.executable} -m seatbelt hook")
    assert [c for _, c in hook.calls] == ["git push --force origin main", "ls"]
    assert all("seatbelt hook" in cmd for cmd, _ in hook.calls)


def test_a_missing_hook_program_is_the_loudest_failure(tmp_path):
    checks = run(tmp_path, command="/nonexistent/venv/bin/seatbelt hook")
    s = statuses(checks)
    assert s["user: hook program exists"] == FAIL
    assert "non-blocking error" in next(c.detail for c in checks if c.title == "user: hook program exists")


def test_no_hook_at_all_is_a_failure_with_the_fix(tmp_path):
    (tmp_path / "settings.json").write_text("{}")
    checks = doctor.run(str(tmp_path), str(tmp_path), {}, FakeHook(), lambda: NEW, {"user": tmp_path / "settings.json"})
    c = next(c for c in checks if c.title == "no seatbelt hook is installed")
    assert c.status == FAIL and "seatbelt install claude-code --write" in c.fix


def test_a_hook_that_does_not_enforce_fails_the_live_test(tmp_path):
    s = statuses(run(tmp_path, FakeHook(deny=False), command=f"{sys.executable} -m seatbelt hook"))
    assert s["live test: a force-push to main is blocked"] == FAIL
    s = statuses(run(tmp_path, FakeHook(safe_silent=False), command=f"{sys.executable} -m seatbelt hook"))
    assert s["live test: a harmless command (`ls`) is left alone"] == FAIL


def test_a_hook_that_exits_non_zero_or_crashes_fails_the_live_test(tmp_path):
    checks = run(tmp_path, FakeHook(code=127), command=f"{sys.executable} -m seatbelt hook")
    assert [c for c in checks if c.status == FAIL and "exited with 127" in c.detail]

    def boom(*a):
        raise TimeoutError("hung")
    checks = run(tmp_path, boom, command=f"{sys.executable} -m seatbelt hook")
    assert [c for c in checks if c.status == FAIL and "TimeoutError" in c.detail]


def test_on_failure_block_is_flagged_only_when_the_claude_code_version_supports_it(tmp_path):
    kw = dict(command=f"{sys.executable} -m seatbelt hook", on_failure=False)
    assert statuses(run(tmp_path, ver=NEW, **kw))["user: a failing hook lets commands through"] == WARN
    assert statuses(run(tmp_path, ver=OLD_CLAUDE, **kw))["user: onFailure=block not available"] == INFO


def test_disable_all_hooks_is_caught(tmp_path):
    s = statuses(run(tmp_path, command=f"{sys.executable} -m seatbelt hook", extra={"disableAllHooks": True}))
    assert FAIL in [v for k, v in s.items() if "settings" in k]


def test_an_old_matcher_and_missing_learn_events_are_reported(tmp_path):
    checks = run(tmp_path, command=f"{sys.executable} -m seatbelt hook", matcher="Bash", events=("PreToolUse",))
    s = statuses(checks)
    assert s["user: matcher is out of date"] == WARN and s["user: learn mode is not recording"] == INFO


def test_invalid_settings_json_and_broken_config(tmp_path):
    bad = tmp_path / "settings.json"
    bad.write_text("{nope")
    checks = doctor.run(str(tmp_path), str(tmp_path), {}, FakeHook(), lambda: NEW, {"user": bad})
    assert any(c.status == FAIL and "not valid JSON" in c.detail for c in checks)
    cfg = tmp_path / ".config" / "seatbelt" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("not = [valid")
    checks = run(tmp_path, command=f"{sys.executable} -m seatbelt hook")
    assert statuses(checks)["configuration"] == FAIL


def test_a_project_file_that_tries_to_allow_is_a_warning(tmp_path):
    (tmp_path / "seatbelt.toml").write_text('[[allow]]\ncommand = "*"\n')
    checks = run(tmp_path, command=f"{sys.executable} -m seatbelt hook")
    assert any(c.status == WARN and "ignored in a project file" in c.detail for c in checks)


def test_doctor_runs_the_real_hook_for_real(tmp_path, monkeypatch):
    """End to end without fakes: install into a temp settings file, then let the doctor run what was installed."""
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = tmp_path / ".claude" / "settings.json"
    assert main(["install", "claude-code", "--settings-file", str(settings), "--write"]) == 0
    checks = doctor.run(str(tmp_path), str(tmp_path), {}, settings_paths={"user": settings})
    live = [c for c in checks if c.title.startswith("live test")]
    assert len(live) == 2 and all(c.status == OK for c in live), live


def test_cli_doctor_exit_code_and_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert main(["doctor", "--json"]) == 1  # nothing installed under this fake home
    rows = json.loads(capsys.readouterr().out)
    assert any(r["status"] == "fail" and r["title"] == "no seatbelt hook is installed" for r in rows)


# ---------------------------------------------------------------- demo

def test_every_demo_scenario_behaves_as_documented():
    text, wrong = demo.run_demo()
    assert wrong == [], wrong
    assert "blocked" in text and "would ask first" in text and "left alone" in text


def test_demo_covers_all_three_verdicts_and_does_not_touch_the_environment(monkeypatch):
    monkeypatch.setenv("SEATBELT_PREVIEW", "on")
    levels = {lvl for _, items in demo.SCENARIOS for lvl, _ in items}
    assert levels == {Level.ALLOW, Level.ASK, Level.DENY}
    demo.run_demo()
    import os
    assert os.environ["SEATBELT_PREVIEW"] == "on"


def test_cli_demo(capsys):
    assert main(["demo", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "git push --force origin main" in out and "DENY" in out and "ALLOW" in out


def test_short_demo_shows_three_examples_per_scenario():
    full, _ = demo.run_demo()
    short, wrong = demo.run_demo(short=True)
    assert wrong == [] and len(short.splitlines()) < len(full.splitlines()) - 10
    assert short.count("ALLOW") == 3 and "git push --force origin main" in short


# ---------------------------------------------------------------- a hook inside a throwaway virtualenv

def make_venv(tmp_path, name="myenv"):
    env = tmp_path / name
    (env / "bin").mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n")
    prog = env / "bin" / "python3"
    prog.write_text("#!/bin/sh\n")
    prog.chmod(0o755)
    return prog


def test_an_ordinary_virtualenv_is_fragile_but_tool_installers_are_not(tmp_path):
    prog = make_venv(tmp_path)
    assert install.is_fragile_python_env(str(prog))
    assert not install.is_fragile_python_env("/usr/bin/python3")
    assert not install.is_fragile_python_env(str(tmp_path / "home/.local/pipx/venvs/seatbelt-guard/bin/python3"))
    assert not install.is_fragile_python_env("/home/me/.local/share/uv/tools/seatbelt-guard/bin/python")


def test_doctor_warns_when_the_hook_lives_in_a_virtualenv(tmp_path):
    prog = make_venv(tmp_path)
    checks = run(tmp_path, command=f"{prog} -m seatbelt hook")
    c = next(c for c in checks if c.title == "user: the hook lives in a virtual environment")
    assert c.status == WARN and "pipx install seatbelt-guard" in c.fix


def test_doctor_is_quiet_for_a_stable_interpreter(tmp_path):
    checks = run(tmp_path, command="/bin/true seatbelt hook")
    assert not [c for c in checks if "virtual environment" in c.title]


def test_install_prints_the_warning_when_run_from_a_virtualenv(tmp_path, monkeypatch, capsys):
    prog = make_venv(tmp_path)
    monkeypatch.setattr(install, "hook_command", lambda headless=False: f"{prog} -m seatbelt hook")
    assert main(["install", "claude-code", "--settings-file", str(tmp_path / "s.json")]) == 0
    err = capsys.readouterr().err
    assert "WARNING" in err and "pipx install seatbelt-guard" in err
    monkeypatch.setattr(install, "hook_command", lambda headless=False: "/usr/bin/python3 -m seatbelt hook")
    main(["install", "claude-code", "--settings-file", str(tmp_path / "s2.json")])
    assert "WARNING" not in capsys.readouterr().err
