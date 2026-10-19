"""Rules that need to see how commands are connected: secret -> network, download -> execute, decode -> execute."""
from __future__ import annotations

from collections import defaultdict

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import SHELLS, Command, parse
from .common import prod_signal
from .db import SQL_CLIENTS, scan_sql
from .interp import INTERPRETERS, _lang, _script_arg, inline_code, scan_code
from .network import FETCHERS, destination, is_network_sink, sends_data
from .secrets import secret_source_reason

ASK, DENY = Level.ASK, Level.DENY
DECODERS = {"base64", "base32", "xxd", "openssl", "gunzip", "zcat", "bzcat", "xzcat", "rev", "uudecode", "gpg"}


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def _is_decoder(cmd: Command) -> bool:
    n, a = cmd.name, cmd.argv[1:]
    if n in ("base64", "base32"):
        return any(x in ("-d", "-D", "--decode") for x in a)
    if n == "xxd":
        return "-r" in a
    if n == "openssl":
        return "-d" in a or "-base64" in a and "-d" in a
    if n == "gpg":
        return "-d" in a or "--decrypt" in a
    return n in ("gunzip", "zcat", "bzcat", "xzcat", "rev", "uudecode")


def _runs_stdin(cmd: Command) -> bool:
    """A shell or interpreter that executes whatever is piped into it."""
    if not cmd.pipe_in:
        return False
    if cmd.name in SHELLS:
        return not any(a.startswith("-") and not a.startswith("--") and "c" in a[1:] for a in cmd.argv[1:]) \
            and (not [a for a in cmd.argv[1:] if not a.startswith("-")] or "-s" in cmd.argv[1:] or "-" in cmd.argv[1:])
    lang = _lang(cmd)
    return bool(lang) and not inline_code(cmd, lang) and (_script_arg(cmd, lang) in (None, "-"))


def analyze_pipelines(commands: list[Command], ctx: Context, res: Resolver) -> list[Finding]:
    out: list[Finding] = []
    groups: dict[int, list[Command]] = defaultdict(list)
    for c in commands:
        groups[c.pipeline].append(c)

    for cmds in groups.values():
        linked = [c for c in cmds if c.pipe_in or c.pipe_out]
        for i, c in enumerate(linked):
            if c.pipe_in and is_network_sink(c) and sends_data(c):
                for src in linked[:i]:
                    why = secret_source_reason(src, ctx, res)
                    if why:
                        out.append(F("exfil.pipe", DENY, "exfiltration", f"pipes {why} into `{c.name}` ({destination(c)})", c))
                        break
            if c.pipe_in and c.name in SQL_CLIENTS:  # echo "DROP TABLE users" | psql
                for p in linked[:i]:
                    if p.name in ("echo", "printf"):
                        out += scan_sql(" ".join(a for a in p.argv[1:] if not a.startswith("-")), prod_signal(c, ctx), c, "piped SQL")
                    elif p.name == "cat":
                        for r in p.redirects:
                            if r.op in ("<<", "<<-", "<<<") and (r.body or r.target):
                                out += scan_sql(r.body or r.target, prod_signal(c, ctx), c, "piped SQL")
            if _runs_stdin(c):
                before = linked[:i]
                if any(p.name in FETCHERS for p in before):
                    out.append(F("exec.download-and-run", ASK, "remote-code", "runs a script straight from the network without anyone reading it", c))
                elif any(_is_decoder(p) for p in before):
                    out.append(F("exec.decoded", ASK, "dynamic", "runs content that was decoded on the fly, which hides what it does", c))
                lang = _lang(c)
                if lang:  # `echo "code" | python`: the producer's literal text is the program
                    for p in before:
                        if p.name in ("echo", "printf"):
                            out += scan_code(" ".join(a for a in p.argv[1:] if not a.startswith("-")), c, ctx, res, f"piped {lang} code", True)

    for c in commands:  # bash <(curl ...), eval "$(curl ...)", sh -c "$(wget -qO- ...)"
        if c.name in SHELLS or c.name in ("eval", "source", "."):
            for w in c.words:
                for sub in w.subs:
                    if any(x.name in FETCHERS for x in parse(sub).commands):
                        out.append(F("exec.download-and-run", ASK, "remote-code", "runs code fetched from the network without anyone reading it", c))
                        break

    fetched: set[str] = set()  # curl -o x.sh URL && bash x.sh
    for c in commands:
        if c.name in FETCHERS:
            argv = c.argv
            for i, a in enumerate(argv[:-1]):
                if a in ("-o", "--output", "-O") and not argv[i + 1].startswith("-") and a != "-O":
                    fetched.add(argv[i + 1])
                if a == "-O" and c.name == "wget" and not argv[i + 1].startswith("-"):
                    fetched.add(argv[i + 1])
            if c.name == "curl" and any(a in ("-O", "--remote-name") for a in argv):
                fetched.update(a.rsplit("/", 1)[-1] for a in argv if "://" in a)
            for r in c.redirects:
                if r.op in (">", ">>") and r.target:
                    fetched.add(r.target)
        elif fetched and (c.name in SHELLS or _lang(c) or c.words[0].text in fetched or c.argv[0].lstrip("./") in {f.lstrip("./") for f in fetched}):
            if any(a in fetched or a.lstrip("./") in {f.lstrip("./") for f in fetched} for a in c.argv):
                out.append(F("exec.download-and-run", ASK, "remote-code", "runs a file that was downloaded earlier in the same command", c))
    return out


__all__ = ["analyze_pipelines", "INTERPRETERS"]
