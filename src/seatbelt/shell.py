"""A small, defensive shell command-line parser.

Goal: find every command a line of shell would really run, including the ones hidden inside `bash -c`, `$(...)`,
`ssh host "..."`, `xargs`, `find -exec`, backslash/quote tricks (`r""m`, `\\rm`) and ANSI-C quoting (`$'\\x72m'`).

It does not try to be a complete POSIX shell. When it cannot tell what will run (a computed command name, an `eval`
of a variable, an unbalanced quote) it records a *problem* instead of guessing, and the engine fails closed on those.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

MAX_DEPTH = 6
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
NAME_CHARS = re.compile(r"[A-Za-z0-9_]")
STRIP_KEYWORDS = {"then", "else", "do", "{", "!", "if", "elif", "while", "until"}
DROP_KEYWORDS = {"for", "select", "case", "function", "fi", "done", "esac", "}", "in"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "busybox"}


@dataclass
class Word:
    text: str
    dyn: bool = False  # contains $var, $(...), `...` or ${...}: its value is not known statically
    glob: bool = False  # contains an unquoted * ? [
    subs: list[str] = field(default_factory=list)  # command substitutions found inside the word


@dataclass
class Redirect:
    op: str  # > >> < << <<< >& &> ...
    target: str
    fd: str = ""
    body: str = ""  # heredoc body


@dataclass
class Command:
    words: list[Word]
    raw: str = ""
    env: dict[str, str] = field(default_factory=dict)
    redirects: list[Redirect] = field(default_factory=list)
    pipe_in: bool = False
    pipe_out: bool = False
    pipeline: int = 0
    via: tuple[str, ...] = ()  # wrappers/contexts this command was found inside: ("sudo", "bash -c", "ssh")
    remote: bool = False  # runs on another machine / in a container (ssh, kubectl exec, docker exec)
    stdin_args: bool = False  # extra, unknown arguments arrive on stdin (xargs) or via find's {}
    cwd: Optional[str] = None  # working directory after preceding `cd`s; None = unknown

    @property
    def argv(self) -> list[str]:
        return [w.text for w in self.words]

    @property
    def name(self) -> str:
        return os.path.basename(self.words[0].text) if self.words else ""

    def dyn(self, i: int) -> bool:
        return 0 <= i < len(self.words) and self.words[i].dyn

    @property
    def privileged(self) -> bool:
        return any(v in ("sudo", "doas", "su") for v in self.via)


@dataclass
class Problem:
    kind: str  # dynamic-command | eval | unbalanced | too-deep
    message: str
    raw: str = ""


@dataclass
class Parsed:
    commands: list[Command]
    problems: list[Problem]


# --------------------------------------------------------------------------- tokenizer

@dataclass
class Tok:
    kind: str  # word | op | redir
    word: Optional[Word] = None
    op: str = ""
    redirect: Optional[Redirect] = None


def _find_close(s: str, i: int, open_c: str = "(", close_c: str = ")") -> int:
    """Index of the bracket matching s[i], skipping quotes and escapes; -1 if unbalanced."""
    depth, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                i += 2 if s[i] == "\\" else 1
            i += 1
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


_ANSI_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "E": "\x1b",
                "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(s: str, i: int) -> tuple[str, int]:
    """Decode $'...' starting at the opening quote index i; returns (text, index after closing quote)."""
    out, n = [], len(s)
    i += 1
    while i < n and s[i] != "'":
        c = s[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = s[i + 1]
        if d == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
                continue
        if d in "01234567":
            m = re.match(r"[0-7]{1,3}", s[i + 1:])
            out.append(chr(int(m.group(), 8) & 0xFF))
            i += 1 + len(m.group())
            continue
        if d == "u" or d == "U":
            m = re.match(r"[0-9a-fA-F]{1,8}" if d == "U" else r"[0-9a-fA-F]{1,4}", s[i + 2:])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
                continue
        out.append(_ANSI_SIMPLE.get(d, d))
        i += 2
    return "".join(out), i + 1


class _Lexer:
    def __init__(self, s: str):
        self.s = s
        self.toks: list[Tok] = []
        self.problems: list[Problem] = []
        self.buf: list[str] = []
        self.has = False
        self.dyn = False
        self.glob = False
        self.subs: list[str] = []
        self.pending_heredocs: list[tuple[Redirect, str, bool]] = []

    def flush(self) -> None:
        if self.has:
            self.toks.append(Tok("word", Word("".join(self.buf), self.dyn, self.glob, self.subs)))
        self.buf, self.has, self.dyn, self.glob, self.subs = [], False, False, False, []

    def op(self, value: str) -> None:
        self.flush()
        self.toks.append(Tok("op", op=value))

    def unbalanced(self, what: str) -> None:
        self.problems.append(Problem("unbalanced", f"unbalanced {what}", self.s[:80]))

    def run(self) -> None:
        s, n, i = self.s, len(self.s), 0
        while i < n:
            c = s[i]
            if c in " \t":
                self.flush()
                i += 1
            elif c == "\n":
                self.op("\n")
                i = self._read_heredocs(i + 1)
            elif c == "#" and not self.has:
                while i < n and s[i] != "\n":
                    i += 1
            elif c == "\\":
                if i + 1 < n and s[i + 1] == "\n":
                    i += 2
                elif i + 1 < n:
                    self.buf.append(s[i + 1])
                    self.has = True
                    i += 2
                else:
                    i += 1
            elif c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    self.unbalanced("single quote")
                    self.buf.append(s[i + 1:])
                    self.has = True
                    i = n
                else:
                    self.buf.append(s[i + 1:j])
                    self.has = True
                    i = j + 1
            elif c == '"':
                i = self._double_quoted(i)
            elif c == "$":
                i = self._dollar(i)
            elif c == "`":
                j = i + 1
                while j < n and s[j] != "`":
                    j += 2 if s[j] == "\\" else 1
                if j >= n:
                    self.unbalanced("backtick")
                    j = n
                self.subs.append(s[i + 1:j].replace("\\`", "`"))
                self.buf.append(s[i:j + 1])
                self.has = self.dyn = True
                i = j + 1
            elif c in "<>" and i + 1 < n and s[i + 1] == "(":
                j = _find_close(s, i + 1)
                if j < 0:
                    self.unbalanced("process substitution")
                    j = n - 1
                self.subs.append(s[i + 2:j])
                self.buf.append(s[i:j + 1])
                self.has = self.dyn = True
                i = j + 1
            elif c in "<>":
                i = self._redirect(i)
            elif c in ";&|()":
                i = self._operator(i)
            else:
                if c in "*?[":
                    self.glob = True
                self.buf.append(c)
                self.has = True
                i += 1
        self.flush()

    def _double_quoted(self, i: int) -> int:
        s, n = self.s, len(self.s)
        i += 1
        self.has = True
        while i < n and s[i] != '"':
            c = s[i]
            if c == "\\" and i + 1 < n:
                if s[i + 1] in '$`"\\\n':
                    if s[i + 1] != "\n":
                        self.buf.append(s[i + 1])
                    i += 2
                else:
                    self.buf.append(c)
                    i += 1
            elif c == "$":
                i = self._dollar(i, in_quotes=True)
            elif c == "`":
                j = s.find("`", i + 1)
                if j < 0:
                    self.unbalanced("backtick")
                    j = n
                self.subs.append(s[i + 1:j])
                self.buf.append(s[i:j + 1])
                self.dyn = True
                i = j + 1
            else:
                self.buf.append(c)
                i += 1
        if i >= n:
            self.unbalanced("double quote")
        return i + 1

    def _dollar(self, i: int, in_quotes: bool = False) -> int:
        s, n = self.s, len(self.s)
        nxt = s[i + 1:i + 2]
        self.has = True
        if nxt == "'" and not in_quotes:
            text, j = _ansi_c(s, i + 1)
            self.buf.append(text)
            return j
        if nxt == "(":
            if s[i + 2:i + 3] == "(":  # $(( arithmetic ))
                j = _find_close(s, i + 1)
                self.buf.append(s[i:j + 1] if j >= 0 else s[i:])
                self.dyn = True
                return j + 1 if j >= 0 else n
            j = _find_close(s, i + 1)
            if j < 0:
                self.unbalanced("$(")
                j = n - 1
            self.subs.append(s[i + 2:j])
            self.buf.append(s[i:j + 1])
            self.dyn = True
            return j + 1
        if nxt == "{":
            j = _find_close(s, i + 1, "{", "}")
            if j < 0:
                self.unbalanced("${")
                j = n - 1
            self.buf.append(s[i:j + 1])
            self.dyn = True
            return j + 1
        if nxt and (NAME_CHARS.match(nxt) or nxt in "@*#?!$-"):
            j = i + 1
            if NAME_CHARS.match(nxt):
                while j < n and NAME_CHARS.match(s[j]):
                    j += 1
            else:
                j += 1
            self.buf.append(s[i:j])
            self.dyn = True
            return j
        self.buf.append("$")
        return i + 1

    def _operator(self, i: int) -> int:
        s = self.s
        two = s[i:i + 2]
        if two in ("&&", "||", "|&"):
            self.op(two)
            return i + 2
        if s[i] == "&" and s[i + 1:i + 2] == ">":
            return self._redirect(i)
        self.op(s[i])
        return i + 1

    def _redirect(self, i: int) -> int:
        s, n = self.s, len(self.s)
        fd = ""
        if self.has and "".join(self.buf).isdigit() and not self.dyn:  # 2>file
            fd = "".join(self.buf)
            self.buf, self.has = [], False
        else:
            self.flush()
        m = re.match(r"(&>>|&>|<<<|<<-|<<|>>|>\||>&|<&|<>|>|<)", s[i:])
        op = m.group(1)
        i += len(op)
        while i < n and s[i] in " \t":
            i += 1
        sub = _Lexer(s[i:])  # read one word as the target
        j = i
        while j < n and s[j] not in " \t\n;&|()<>":
            if s[j] in "'\"":
                q = s[j]
                k = s.find(q, j + 1)
                j = n if k < 0 else k + 1
            elif s[j] == "\\":
                j += 2
            elif s[j] == "$" and s[j + 1:j + 2] == "(":
                k = _find_close(s, j + 1)
                j = n if k < 0 else k + 1
            else:
                j += 1
        sub.s = s[i:j]
        sub.run()
        target = sub.toks[0].word.text if sub.toks and sub.toks[0].kind == "word" else ""
        extra_subs = sub.toks[0].word.subs if sub.toks and sub.toks[0].kind == "word" else []
        red = Redirect(op, target, fd)
        self.toks.append(Tok("redir", redirect=red))
        for e in extra_subs:  # `> $(cmd)` still runs cmd
            self.toks.append(Tok("word", Word(f"$({e})", True, False, [e])))
            self.toks.append(Tok("op", op="\n"))
        if op in ("<<", "<<-"):
            self.pending_heredocs.append((red, target, op == "<<-"))
        return j

    def _read_heredocs(self, i: int) -> int:
        s, n = self.s, len(self.s)
        for red, delim, strip in self.pending_heredocs:
            lines = []
            while i < n:
                j = s.find("\n", i)
                line = s[i:] if j < 0 else s[i:j]
                i = n if j < 0 else j + 1
                if (line.lstrip("\t") if strip else line) == delim:
                    break
                lines.append(line)
            red.body = "\n".join(lines)
        self.pending_heredocs = []
        return i


# --------------------------------------------------------------------------- command builder

def _skip_opts(args: list[Word], with_value: set[str] = frozenset()) -> int:
    i = 0
    while i < len(args):
        a = args[i].text
        if a == "--":
            return i + 1
        if not a.startswith("-") or a == "-":
            return i
        i += 2 if a in with_value else 1
    return i


_WRAPPERS_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-T", "-r", "-t", "-U", "-D", "--user", "--group", "--host", "--prompt", "--chdir"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "nohup": set(), "setsid": set(), "unbuffer": set(), "builtin": set(),
    "time": {"-f", "-o", "--format", "--output"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u"},
    "stdbuf": {"-i", "-o", "-e"},
    "exec": {"-a"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "xargs": {"-I", "-n", "-P", "-L", "-l", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--max-lines", "--delimiter", "--arg-file"},
}
_SSH_VALUE_OPTS = {"-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S", "-w", "-W"}


@dataclass
class _Inner:
    words: Optional[list[Word]] = None  # inner argv
    script: Optional[str] = None  # inner shell script to parse
    via: str = ""
    remote: bool = False
    stdin_args: bool = False
    dynamic_script: bool = False


def _unwrap(words: list[Word]) -> list[_Inner]:
    name = os.path.basename(words[0].text)
    args = words[1:]
    out: list[_Inner] = []

    if name in ("sudo", "doas", "env", "nohup", "setsid", "unbuffer", "builtin", "time", "nice", "ionice",
                "stdbuf", "exec", "timeout", "xargs", "command"):
        if name == "command" and any(a.text in ("-v", "-V") for a in args):
            return out
        i = _skip_opts(args, _WRAPPERS_VALUE_OPTS.get(name, set()))
        if name == "timeout" and i < len(args):
            i += 1  # the duration
        while name in ("sudo", "env") and i < len(args) and ASSIGN.match(args[i].text):
            i += 1
        if i < len(args):
            out.append(_Inner(words=args[i:], via=name, stdin_args=(name == "xargs")))
        return out

    if name == "su":
        for j, a in enumerate(args):
            if a.text in ("-c", "--command") and j + 1 < len(args):
                out.append(_Inner(script=args[j + 1].text, via="su", dynamic_script=args[j + 1].dyn))
        return out

    if name in SHELLS:
        i = 0
        while i < len(args):
            t = args[i].text
            if t == "--":
                break
            if t.startswith("-") and not t.startswith("--") and "c" in t[1:]:
                if i + 1 < len(args):
                    out.append(_Inner(script=args[i + 1].text, via=f"{name} -c", dynamic_script=args[i + 1].dyn))
                break
            if not t.startswith("-"):
                break
            i += 1
        return out

    if name == "eval":
        out.append(_Inner(script=" ".join(a.text for a in args), via="eval", dynamic_script=any(a.dyn for a in args)))
        return out

    if name == "ssh":
        i = _skip_opts(args, _SSH_VALUE_OPTS)
        rest = args[i + 1:]  # args[i] is the host
        if rest:
            out.append(_Inner(script=" ".join(a.text for a in rest), via="ssh", remote=True,
                              dynamic_script=any(a.dyn for a in rest)))
        return out

    if name in ("kubectl", "oc") and any(a.text == "exec" for a in args) and any(a.text == "--" for a in args):
        k = next(j for j, a in enumerate(args) if a.text == "--")
        if k + 1 < len(args):
            out.append(_Inner(words=args[k + 1:], via=f"{name} exec", remote=True))
        return out

    if name in ("docker", "podman") and args and args[0].text == "exec":
        i = 1 + _skip_opts(args[1:], {"-u", "--user", "-w", "--workdir", "-e", "--env", "--env-file", "--detach-keys"})
        if i + 1 < len(args):  # args[i] is the container
            out.append(_Inner(words=args[i + 1:], via=f"{name} exec", remote=True))
        return out

    if name == "find":
        j = 0
        while j < len(args):
            if args[j].text in ("-exec", "-execdir", "-ok", "-okdir"):
                k = j + 1
                while k < len(args) and args[k].text not in (";", "+"):
                    k += 1
                if k > j + 1:
                    out.append(_Inner(words=args[j + 1:k], via="find -exec", stdin_args=True))
                j = k
            j += 1
        return out
    return out


class Parser:
    def __init__(self) -> None:
        self.problems: list[Problem] = []
        self.commands: list[Command] = []
        self._pid = 0

    def parse(self, text: str, via: tuple[str, ...] = (), remote: bool = False, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            self.problems.append(Problem("too-deep", "commands are nested too deeply to analyse", text[:80]))
            return
        lx = _Lexer(text)
        lx.run()
        self.problems.extend(lx.problems)
        toks, n = lx.toks, len(lx.toks)

        words: list[Word] = []
        redirs: list[Redirect] = []
        env: dict[str, str] = {}
        pipe_in = False
        pid = self._new_pipeline()

        def finish(pipe_out: bool) -> None:
            nonlocal words, redirs, env, pipe_in
            if words:
                self._emit(words, env, redirs, pipe_in, pipe_out, pid_holder[0], via, remote, depth)
            elif env or redirs:
                self._scan_assignments(env, via, remote, depth, pid_holder[0])
            words, redirs, env = [], [], {}
            pipe_in = pipe_out

        pid_holder = [pid]
        i = 0
        while i < n:
            t = toks[i]
            i += 1
            if t.kind == "word":
                w = t.word
                if not words and ASSIGN.match(w.text) and not w.text.startswith("="):
                    k, _, v = w.text.partition("=")
                    env[k.rstrip("+")] = v
                    for sub in w.subs:
                        self.parse(sub, via + ("$(...)",), remote, depth + 1)
                    continue
                if not words and w.text in STRIP_KEYWORDS and not w.dyn:
                    continue
                if not words and w.text in DROP_KEYWORDS and not w.dyn:
                    while i < n and not (toks[i].kind == "op" and toks[i].op in (";", "\n", "&&", "||")):
                        i += 1
                    continue
                words.append(w)
            elif t.kind == "redir":
                redirs.append(t.redirect)
            else:
                op = t.op
                if op in ("|", "|&"):
                    finish(True)
                elif op in (";", "\n", "&&", "||", "&", "(", ")"):
                    finish(False)
                    pid_holder[0] = self._new_pipeline()
        finish(False)

    def _new_pipeline(self) -> int:
        self._pid += 1
        return self._pid

    def _scan_assignments(self, env, via, remote, depth, pid) -> None:
        pass  # substitutions in assignments were already parsed in parse()

    def _emit(self, words, env, redirs, pipe_in, pipe_out, pid, via, remote, depth) -> None:
        raw = " ".join(w.text for w in words)
        cmd = Command(list(words), raw, dict(env), list(redirs), pipe_in, pipe_out, pid, via, remote)
        self.commands.append(cmd)
        if words[0].dyn:
            self.problems.append(Problem("dynamic-command", f"the command name `{words[0].text}` is computed at runtime", raw))
        for w in words:
            for sub in w.subs:
                self.parse(sub, via + ("$(...)",), remote, depth + 1)
        for r in redirs:
            if r.op in ("<<", "<<-") and cmd.name in SHELLS and r.body:
                self.parse(r.body, via + (f"{cmd.name} <<",), remote, depth + 1)
        for inner in _unwrap(words):
            nvia = via + ((inner.via,) if inner.via else ())
            if inner.script is not None:
                if inner.via == "eval" and inner.dynamic_script:
                    self.problems.append(Problem("eval", f"`{inner.via}` runs a string that is built at runtime", raw))
                self.parse(inner.script, nvia, remote or inner.remote, depth + 1)
            elif inner.words:
                before = len(self.commands)
                self._emit(inner.words, {}, [], False, False, pid, nvia, remote or inner.remote, depth + 1)
                if inner.stdin_args:
                    self.commands[before].stdin_args = True


def _shell_reads_stdin(cmd: Command) -> bool:
    """`bash`, `sh -s`, `bash -` ...: a shell that will execute whatever is piped into it."""
    if cmd.name not in SHELLS:
        return False
    rest = [a for a in cmd.argv[1:] if not a.startswith("-") or a == "-"]
    has_c = any(a.startswith("-") and not a.startswith("--") and "c" in a[1:] for a in cmd.argv[1:])
    return not has_c and (not rest or rest == ["-"] or "-s" in cmd.argv[1:])


def parse(text: str) -> Parsed:
    p = Parser()
    p.parse(text)
    # `echo "rm -rf /" | bash` / `cat <<EOF | sh`: the producer's literal text *is* the script, so analyse it too
    by_pipeline: dict[int, list[Command]] = {}
    for c in p.commands:
        by_pipeline.setdefault(c.pipeline, []).append(c)
    for cmds in by_pipeline.values():
        if not any(c.pipe_in and _shell_reads_stdin(c) for c in cmds):
            continue
        for c in cmds:
            if c.name in ("echo", "printf") and c.pipe_out:
                p.parse(" ".join(a for a in c.argv[1:] if not a.startswith("-")), c.via + ("piped to shell",), c.remote, 1)
            elif c.name == "cat" and c.pipe_out:
                for r in c.redirects:
                    if r.op in ("<<", "<<-", "<<<") and (r.body or r.target):
                        p.parse(r.body or r.target, c.via + ("piped to shell",), c.remote, 1)
    return Parsed(p.commands, p.problems)
