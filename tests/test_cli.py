import json
from pathlib import Path

import pytest

from seatbelt.cli import main

CORPUS = str(Path(__file__).parent.parent / "examples" / "commands.txt")
CTX = ["--cwd", "/work/project", "--home", "/home/dev"]


def test_exit_codes_mirror_the_verdict(capsys):
    assert main(["check", *CTX, "ls", "-la"]) == 0
    assert main(["check", *CTX, "rm", "-rf", "src"]) == 1
    assert main(["check", *CTX, "rm -rf ~"]) == 2
    out = capsys.readouterr().out
    assert "DENY" in out and "[fs.rm.protected]" in out


def test_json_output(capsys):
    assert main(["check", "--json", *CTX, "git push -f origin main"]) == 2
    d = json.loads(capsys.readouterr().out)
    assert d["decision"] == "deny" and d["findings"][0]["rule"] == "git.push.force"


def test_headless_flag(capsys):
    assert main(["check", "--headless", *CTX, "rm -rf src"]) == 2


def test_file_mode_checks_the_whole_corpus(capsys):
    assert main(["check", "--file", CORPUS, "--no-color", *CTX]) == 0
    out = capsys.readouterr().out
    assert "rm -rf /" in out and "!!" not in out


def test_file_mode_reports_mismatches(tmp_path, capsys):
    f = tmp_path / "c.txt"
    f.write_text("ALLOW\trm -rf /\n")
    assert main(["check", "--file", str(f), "--no-color", *CTX]) == 1
    assert "expected ALLOW" in capsys.readouterr().out


def test_missing_command_is_an_error(capsys):
    assert main(["check", *CTX]) == 2


def test_no_subcommand_exits(capsys):
    with pytest.raises(SystemExit):
        main([])
