import random
import string

import pytest

from seatbelt.context import Context
from seatbelt.engine import analyze
from seatbelt.model import Level

CTX = dict(cwd="/work/project", home="/home/dev", environ={})


def level(cmd, **kw):
    return analyze(cmd, Context(**{**CTX, **kw})).level


def test_headless_turns_every_ask_into_deny():
    assert level("rm -rf src") == Level.ASK
    assert level("rm -rf src", headless=True) == Level.DENY
    assert level("ls", headless=True) == Level.ALLOW


def test_relative_paths_follow_cd():
    assert level("cd /tmp && rm -rf cache") == Level.ALLOW
    assert level("cd /etc && rm -rf *") == Level.DENY
    assert level("cd $SOMEWHERE && rm -rf data") == Level.ASK  # unknown directory


def test_cwd_matters_for_deleting_the_project_itself():
    assert level("rm -rf /work/project") == Level.ASK
    assert level("rm -rf /work") == Level.ASK
    assert level("rm -rf /work/project/src/old") == Level.ASK


def test_build_dirs_only_get_a_pass_inside_the_project():
    assert level("rm -rf node_modules") == Level.ALLOW
    assert level("rm -rf /home/dev/other/node_modules") == Level.ASK


def test_verdict_explains_itself():
    v = analyze("git push --force origin main", Context(**CTX))
    assert v.level == Level.DENY and "protected branch" in v.reason and v.findings[0].rule == "git.push.force"


def test_json_shape():
    d = analyze("rm -rf ~", Context(**CTX)).to_dict()
    assert d["decision"] == "deny" and d["findings"][0]["category"] == "irreversible"


@pytest.mark.parametrize("cmd", [
    "git log --oneline", "git diff HEAD~1", "git push origin HEAD", "git stash", "git stash pop", "git branch -d merged",
    "git checkout -b new", "git checkout main", "git restore --staged f.txt", "git reset HEAD f.txt", "git reset --soft HEAD~1",
    "rm build/output.o", "rm -f ./tmp.log", "mkdir -p x && touch x/y", "chmod 755 run.sh", "chmod -R u+rwX src",
    "find . -type f -name '*.tmp' -delete", "dd if=a.img of=/dev/null", "fdisk -l", "kill 1234", "kill -9 4321",
    "systemctl status nginx", "echo rm -rf / is dangerous", "grep -r 'rm -rf' .", "ls /",
])
def test_ordinary_commands_are_not_flagged(cmd):
    assert level(cmd) == Level.ALLOW, analyze(cmd, Context(**CTX)).reason


def test_engine_never_raises_on_garbage():
    """A crash in a hook lets the command through, so the engine must survive anything."""
    rng = random.Random(1234)
    alphabet = string.printable + "'\"`$(){}[]\\|&;<>*?~#!"
    pieces = ["rm", "-rf", "/", "$(", ")", "`", "'", '"', "bash -c", "sudo", "|", "&&", "<<EOF", "\n", "$'", "\\x", "{}", "xargs",
              "find", "-exec", "ssh", "eval", "cd", "~", "$HOME", "${", "<(", "git push -f"]
    for _ in range(3000):
        n = rng.randint(1, 12)
        text = " ".join(rng.choice(pieces) if rng.random() < 0.6 else "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 8)))
                        for _ in range(n))
        analyze(text, Context(**CTX))


def test_a_project_that_lives_in_tmp_is_still_a_project():
    assert level("rm -rf /tmp/scratch-1", cwd="/work/project") == Level.ALLOW
    assert level("rm -rf src", cwd="/tmp/myproj") == Level.ASK
    assert level("rm -rf /tmp/myproj/src", cwd="/tmp/myproj") == Level.ASK
    assert level("rm -rf node_modules", cwd="/tmp/myproj") == Level.ALLOW
