import os
import time

from seatbelt import hook, preview
from seatbelt.context import Context
from seatbelt.engine import analyze
from seatbelt.model import Level


def make_tree(root, files=5, size=100, old=False):
    root.mkdir(parents=True, exist_ok=True)
    for i in range(files):
        f = root / f"f{i}.txt"
        f.write_text("x" * size)
        if old:
            t = time.time() - 10 * 86400
            os.utime(f, (t, t))
    return root


def test_measure_counts_files_folders_and_bytes(tmp_path):
    root = make_tree(tmp_path / "src", files=4, size=250, old=True)
    make_tree(root / "sub" / "deeper", files=2, size=50, old=True)
    t = preview.measure(str(root))
    assert (t.files, t.dirs, t.bytes) == (6, 3, 4 * 250 + 2 * 50)
    assert t.recent == 0 and not t.has_git and not t.truncated


def test_recent_changes_are_flagged_as_possible_uncommitted_work(tmp_path):
    root = make_tree(tmp_path / "src", files=3, old=True)
    (root / "new.py").write_text("print(1)")
    t = preview.measure(str(root))
    assert t.recent == 1
    assert "1 file changed in the last 24 hours" in preview.describe_tree(str(root), t)


def test_git_history_is_flagged_not_walked(tmp_path):
    root = make_tree(tmp_path / "proj", files=2, old=True)
    make_tree(root / ".git" / "objects", files=50)
    t = preview.measure(str(root))
    assert t.has_git and t.files == 2  # the 50 objects were not counted
    assert "includes a .git directory" in preview.describe_tree(str(root), t)


def test_files_unlikely_to_be_in_version_control_are_named(tmp_path):
    root = make_tree(tmp_path / "app", files=1, old=True)
    for name in (".env", "local.sqlite3", "server.pem", ".env.example", "notes.txt"):
        (root / name).write_text("x")
    t = preview.measure(str(root))
    assert set(t.irreplaceable) == {".env", "local.sqlite3", "server.pem"}  # not .env.example


def test_symlinks_are_not_followed(tmp_path):
    root = make_tree(tmp_path / "a", files=2, old=True)
    (root / "loop").symlink_to(root)
    (root / "out").symlink_to(tmp_path)
    t = preview.measure(str(root))
    assert t.files == 4 and t.dirs == 1  # the two links count as files; nothing outside or looping is walked


def test_huge_trees_stop_early_and_say_so(tmp_path):
    root = make_tree(tmp_path / "big", files=600, size=1)
    t = preview.measure(str(root), max_entries=300)
    assert t.truncated and "at least" in preview.describe_tree(str(root), t)
    t = preview.measure(str(root), budget=-1)  # budget already spent
    assert t.truncated


def test_time_budget_keeps_the_hook_fast(tmp_path):
    root = make_tree(tmp_path / "many", files=3000, size=1)
    start = time.monotonic()
    t = preview.measure(str(root))
    assert t.files == 3000 and time.monotonic() - start < 1.5


def test_missing_paths_and_virtual_filesystems():
    assert preview.measure("/definitely/not/here") is None
    t = preview.measure("/proc")
    assert t.truncated and t.files == 0  # never walked


def test_single_file_description(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    t = preview.measure(str(f))
    assert preview.describe_tree(str(f), t) == f"deletes the file {f} (5 B), changed in the last 24 hours"


def test_human_units():
    assert preview.human_bytes(0) == "0 B" and preview.human_bytes(1536) == "1.5 KB"
    assert preview.human_bytes(5 * 1024 ** 3) == "5.0 GB"
    assert preview.human_age(30) == "just now" and preview.human_age(3 * 3600) == "3 hours ago"


# ---------------------------------------------------------------- through the engine and the hook

def ctx_for(path):
    return Context(cwd=str(path), home="/home/dev", environ={})


def test_ask_verdicts_carry_the_impact(tmp_path):
    make_tree(tmp_path / "src", files=7, size=100, old=True)
    v = analyze("rm -rf src", ctx_for(tmp_path))
    assert v.level == Level.ASK and len(v.impact) == 1
    assert "7 files in 1 folders (700 B)" in v.impact[0]
    assert "Impact: deletes 7 files" in v.reason
    assert analyze("rm -rf src", ctx_for(tmp_path)).to_dict()["impact"] == v.impact


def test_globs_and_several_targets(tmp_path):
    make_tree(tmp_path / "a", files=2, old=True)
    make_tree(tmp_path / "b", files=3, old=True)
    v = analyze("rm -rf a b", ctx_for(tmp_path))
    assert len(v.impact) == 2 and "2 files" in v.impact[0] and "3 files" in v.impact[1]
    v = analyze("rm -rf /nonexistent-dir-xyz", ctx_for(tmp_path))
    assert v.level == Level.ASK and v.impact == []


def test_find_delete_and_dd_are_previewed(tmp_path):
    make_tree(tmp_path / "logs", files=4, old=True)
    v = analyze("find logs -delete", ctx_for(tmp_path))
    assert v.level == Level.ASK and "4 files" in v.impact[0]
    (tmp_path / "disk.img").write_bytes(b"0" * 2048)
    v = analyze("dd if=/dev/zero of=disk.img", ctx_for(tmp_path))
    assert v.level == Level.ASK and "overwrites the file" in v.impact[0] and "2.0 KB" in v.impact[0]


def test_nothing_is_measured_when_the_command_is_allowed(tmp_path, monkeypatch):
    make_tree(tmp_path / "node_modules", files=3)

    def boom(*a, **k):
        raise AssertionError("measured an allowed command")
    monkeypatch.setattr(preview, "measure", boom)
    v = analyze("rm -rf node_modules", ctx_for(tmp_path))
    assert v.level == Level.ALLOW and v.impact == []


def test_a_failing_preview_never_changes_the_decision(tmp_path, monkeypatch):
    make_tree(tmp_path / "src", files=2)
    monkeypatch.setattr(preview, "measure", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    v = analyze("rm -rf src", ctx_for(tmp_path))
    assert v.level == Level.ASK and v.impact == []


def test_deny_verdicts_do_not_measure_the_disk(tmp_path):
    v = analyze("rm -rf /", ctx_for(tmp_path))
    assert v.level == Level.DENY and not any("under /" in line for line in v.impact)


def test_the_hook_prompt_shows_the_impact(tmp_path):
    make_tree(tmp_path / "src", files=3, size=10, old=True)
    out = hook.handle({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf src"}, "cwd": str(tmp_path)})
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask" and "Impact: deletes 3 files" in reason


def test_many_paths_share_one_budget(tmp_path):
    for i in range(60):
        make_tree(tmp_path / f"d{i}", files=2, old=True)
    start = time.monotonic()
    v = analyze("rm -rf *", ctx_for(tmp_path))
    assert v.level == Level.ASK and time.monotonic() - start < 3
    assert any("60 paths in total" in line for line in v.impact)


def test_a_spent_budget_marks_the_rest_as_not_counted(tmp_path, monkeypatch):
    for i in range(6):
        make_tree(tmp_path / f"d{i}", files=1, old=True)
    monkeypatch.setattr(preview, "BUDGET_SECONDS", -1)
    v = analyze("rm -rf *", ctx_for(tmp_path))
    assert v.level == Level.ASK and any("not counted" in line or "at least" in line for line in v.impact)


def test_filtered_find_is_not_previewed_as_if_it_deleted_everything(tmp_path):
    make_tree(tmp_path / "logs", files=3, old=True)
    assert analyze("find logs -delete", ctx_for(tmp_path)).impact != []
    v = analyze("find / -name '*.log' -delete", ctx_for(tmp_path))
    assert v.level == Level.ASK and v.impact == []


def test_preview_can_be_switched_off(tmp_path, monkeypatch):
    make_tree(tmp_path / "src", files=2)
    monkeypatch.setenv("SEATBELT_PREVIEW", "off")
    v = analyze("rm -rf src", ctx_for(tmp_path))
    assert v.level == Level.ASK and v.impact == []
