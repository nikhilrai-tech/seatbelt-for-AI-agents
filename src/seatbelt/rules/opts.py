from __future__ import annotations

from dataclasses import dataclass, field

from ..shell import Word


@dataclass
class Opts:
    flags: set[str] = field(default_factory=set)  # "-r", "--force"
    values: dict[str, list[str]] = field(default_factory=dict)
    pos: list[Word] = field(default_factory=list)

    def has(self, *names: str) -> bool:
        return any(n in self.flags for n in names)


def parse_words(words: list[Word], takes_value: set[str] | frozenset[str] = frozenset(),
                stop_at_positional: bool = False) -> Opts:
    """Split argv words into flags, option values and positionals. Short clusters (-rf) are expanded."""
    o = Opts()
    i, n = 0, len(words)
    while i < n:
        w = words[i]
        a = w.text
        if a == "--":
            o.pos.extend(words[i + 1:])
            break
        if a.startswith("--") and len(a) > 2:
            name, eq, val = a.partition("=")
            o.flags.add(name)
            if eq:
                o.values.setdefault(name, []).append(val)
            elif name in takes_value and i + 1 < n:
                o.values.setdefault(name, []).append(words[i + 1].text)
                i += 1
        elif a.startswith("-") and len(a) > 1 and not a[1:].isdigit() or (a.startswith("-") and a[1:].isdigit()):
            cluster = a[1:]
            j = 0
            while j < len(cluster):
                ch = cluster[j]
                o.flags.add("-" + ch)
                if "-" + ch in takes_value:
                    rest = cluster[j + 1:]
                    if rest:
                        o.values.setdefault("-" + ch, []).append(rest)
                    elif i + 1 < n:
                        o.values.setdefault("-" + ch, []).append(words[i + 1].text)
                        i += 1
                    break
                j += 1
        else:
            o.pos.append(w)
            if stop_at_positional:
                o.pos.extend(words[i + 1:])
                break
        i += 1
    return o
