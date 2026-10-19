"""Guards against stray files. A stray empty `notes.txt` once got committed because a test corpus was accidentally run as shell
(`ALLOW<TAB>echo hi > notes.txt`: bash creates the redirect target even when the command is not found)."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent
ALLOWED_EMPTY = {"__init__.py", ".gitkeep"}


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None  # not a git checkout (for example an sdist): nothing to check
    return [ROOT / line for line in out.splitlines() if line]


def test_no_tracked_file_is_empty_by_accident():
    files = tracked_files()
    if files is None:
        return
    empty = [str(f.relative_to(ROOT)) for f in files if f.is_file() and f.stat().st_size == 0 and f.name not in ALLOWED_EMPTY]
    assert not empty, f"empty files are tracked: {empty}"


def test_the_repository_root_only_holds_expected_files():
    files = tracked_files()
    if files is None:
        return
    expected = {"README.md", "LICENSE", "NOTICE", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md",
                "pyproject.toml", ".gitignore"}
    stray = sorted(f.name for f in files if f.parent == ROOT and f.name not in expected)
    assert not stray, f"unexpected files in the repository root: {stray}"
