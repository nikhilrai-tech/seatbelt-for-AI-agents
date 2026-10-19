"""examples/commands.txt is the regression suite: every line is `EXPECTED<TAB>command`."""
from pathlib import Path

import pytest

from seatbelt.context import Context
from seatbelt.engine import analyze
from seatbelt.model import Level

CORPUS = Path(__file__).parent.parent / "examples" / "commands.txt"
CTX = dict(cwd="/work/project", home="/home/dev", environ={})


def _cases():
    for raw in CORPUS.read_text().splitlines():
        head, sep, rest = raw.partition("\t")
        if sep and head in Level.__members__:
            yield pytest.param(Level[head], rest, id=rest[:60])


@pytest.mark.parametrize("expected,command", list(_cases()))
def test_corpus_line(expected, command):
    v = analyze(command, Context(**CTX))
    assert v.level == expected, f"{command!r}: got {v.level.name} ({v.reason or 'no findings'})"


def test_corpus_is_not_empty():
    assert len(list(_cases())) > 80
