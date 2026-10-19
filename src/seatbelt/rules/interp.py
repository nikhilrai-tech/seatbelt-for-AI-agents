"""Code the agent hands to an interpreter: `python -c`, here-docs, and script files it just wrote.

A command-level guard is easy to walk around: write `cleanup.py`, then run `python cleanup.py`. So scripts are read
and checked too (regular files only, size-capped, bounded depth).
"""
from __future__ import annotations

import os
import posixpath
import re
import shlex
from typing import Optional

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import SHELLS, Command
from . import rule
from .secrets import secret_kind
from .tamper import protected_kind

ASK, DENY = Level.ASK, Level.DENY
MAX_SCRIPT_BYTES = 256 * 1024
MAX_DEPTH = 3
INTERPRETERS = ("python", "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua")
INLINE_FLAGS = {"python": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
                "ruby": {"-e"}, "perl": {"-e", "-E"}, "php": {"-r"}, "lua": {"-e"}, "bun": {"-e", "--eval"}, "deno": set()}

LITERAL = re.compile(r"""(?P<q>['"])(?P<s>(?:\\.|(?!(?P=q)).)*)(?P=q)""", re.S)
DELETE_CALL = re.compile(r"""(?:shutil\.rmtree|rmtree|os\.(?:remove|unlink|rmdir|removedirs)|rmSync|rmdirSync|unlinkSync|fs\.(?:rm|rmdir|unlink)|File\.delete|FileUtils\.(?:rm_rf|rm_r|rm|remove)|Dir\.rmdir|unlink)\s*\(\s*(?P<q>['"])(?P<p>[^'"]+)(?P=q)""")
DELETE_ANY = re.compile(r"shutil\.rmtree|\brmtree\(|os\.(remove|unlink|rmdir|removedirs)\b|\.unlink\(|\.rmdir\(|rmSync|rmdirSync|unlinkSync|fs\.(rm|rmdir|unlink)\b|fs\.promises\.(rm|unlink)|File\.delete|FileUtils\.(rm|remove)|Dir\.rmdir|\bunlink\s*[(g]|\bremove_tree\b")
EXEC_CALL = re.compile(r"""(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen)|Popen|execSync|exec|spawnSync|spawn|system|shell_exec|passthru|popen)\s*\(\s*(?P<q>['"])(?P<c>(?:\\.|(?!(?P=q)).)*)(?P=q)""", re.S)
EXEC_LIST = re.compile(r"(?:subprocess\.(?:run|call|check_call|check_output|Popen)|Popen|execFileSync|execFile|spawnSync|spawn)\s*\(\s*\[(?P<items>[^\]]*)\]", re.S)
EXEC_ANY = re.compile(r"os\.system|os\.popen|subprocess\.|\bPopen\b|child_process|\bexecSync\b|\bspawnSync\b|\bspawn\(|\bsystem\s*\(|\bexec\s*\(|shell_exec|proc_open|\bpassthru\b|%x\(|Open3|IO\.popen")
OBFUSCATED = re.compile(r"\beval\s*\(|\bexec\s*\(\s*(?:compile|base64|bytes|zlib)|base64\.(?:b64|urlsafe_b64|decodebytes)|\batob\(|Buffer\.from\([^)]*['\"]base64|marshal\.loads|__import__\(|exec\(\s*bytes")
NETWORK = re.compile(r"requests\.|urllib|http\.client|httpx|aiohttp|socket\.|\bfetch\(|XMLHttpRequest|net\.connect|require\(['\"](?:https?|net|dgram)['\"]\)|Net::HTTP|open-uri|curl_exec|file_get_contents\(\s*['\"]https?|LWP|IO::Socket|WebSocket|smtplib|ftplib|paramiko|http\.request|https\.request")
WRITEY = re.compile(r"""['"][wa]b?\+?['"]|\bwrite(?:File|FileSync|_text|_bytes)?\b|appendFile|\brename\b|shutil\.(?:copy|move)|File\.(?:write|open)""")


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def _lang(cmd: Command) -> Optional[str]:
    n = cmd.name
    for base in INTERPRETERS:
        if n == base or (n.startswith(base) and re.fullmatch(r"[0-9.]+", n[len(base):] or "x") is not None):
            return base
    return None


_ONE_LITERAL = re.compile(r"""\s*(['"])(?P<s>(?:\\.|(?!\1).)*)\1\s*""", re.S)
JOIN_CALL = re.compile(r"(?:os\.path\.join|posixpath\.join|path\.join|path\.resolve|File\.join|PurePosixPath|PurePath|Path|Paths\.get)\(((?:[^()]|\([^()]*\))*)\)")
DIV_CHAIN = re.compile(r"""(?:\s*/\s*(?:'[^'\n]*'|"[^"\n]*"))+""")
PLUS_CHAIN = re.compile(r"""(?:'[^'\n]*'|"[^"\n]*")(?:\s*\+\s*(?:'[^'\n]*'|"[^"\n]*"))+""")


def candidate_strings(code: str) -> list[str]:
    """Every string literal in `code`, plus paths that are built from literals (os.path.join, Path / "x", "a" + "b").

    A script can hide `.ssh/id_rsa` by never writing it as one string. A static scan cannot follow variables, but it can
    follow the common ways a path is assembled from constants.
    """
    out = [m.group("s") for m in LITERAL.finditer(code)]
    for m in JOIN_CALL.finditer(code):
        parts = [p for p in re.split(r"\s*,\s*", m.group(1).strip()) if p]
        lits = [x.group("s") for p in parts if (x := _ONE_LITERAL.fullmatch(p))]
        if len(lits) >= 2 or (lits and len(parts) > 1):
            out.append("/".join(s.strip("/") if i else s.rstrip("/") for i, s in enumerate(lits)))
    for m in DIV_CHAIN.finditer(code):
        out.append("/".join(x.group("s").strip("/") for x in LITERAL.finditer(m.group(0))))
    for m in PLUS_CHAIN.finditer(code):
        out.append("".join(x.group("s") for x in LITERAL.finditer(m.group(0))))
    return out


def _shell_join(items: str) -> str:
    parts = [m.group("s") for m in LITERAL.finditer(items)]
    return " ".join(shlex.quote(p) for p in parts)


def scan_code(code: str, cmd: Command, ctx: Context, res: Resolver, where: str, strict: bool) -> list[Finding]:
    """Look for deleting, executing, hiding and exfiltrating in `code` (any common scripting language)."""
    from ..engine import analyze  # late import: the engine imports the rules
    out: list[Finding] = []
    label = f"{where}: " if where else ""
    sub_ctx = Context(cwd=cmd.cwd or ctx.cwd, home=ctx.home, environ=ctx.environ, headless=False, depth=ctx.depth + 1)

    # shell commands passed as literals are analysed as shell
    commands: list[str] = [m.group("c") for m in EXEC_CALL.finditer(code)]
    commands += [_shell_join(m.group("items")) for m in EXEC_LIST.finditer(code)]
    literal_exec = False
    if ctx.depth < MAX_DEPTH:
        for text in commands:
            if text.strip():
                literal_exec = True
                for f in analyze(text, sub_ctx).findings:
                    out.append(Finding(f"code.{f.rule}", f.level, f.category, f"{label}{f.message}", cmd.raw))
    if EXEC_ANY.search(code) and not literal_exec and strict:
        out.append(F("code.exec-dynamic", ASK, "dynamic", f"{label}runs shell commands built at runtime; they cannot be checked", cmd))

    for m in DELETE_CALL.finditer(code):
        r = res.resolve(m.group("p"), cmd.cwd)
        if r.path is None or res.is_system(r.path):
            out.append(F("code.delete-protected", DENY if r.path else ASK, "irreversible",
                         f"{label}deletes files at `{m.group('p')}`" + (" (a system or home directory)" if r.path else ""), cmd))
        else:
            out.append(F("code.delete", ASK, "destructive", f"{label}deletes files (`{m.group('p')}`)", cmd))
    if not DELETE_CALL.search(code) and DELETE_ANY.search(code) and strict:
        out.append(F("code.delete-dynamic", ASK, "destructive", f"{label}deletes files at paths computed at runtime", cmd))

    if OBFUSCATED.search(code):
        out.append(F("code.obfuscated", ASK, "dynamic", f"{label}decodes or evaluates code at runtime, which hides what it does", cmd))

    secrets, protected = [], []
    for s in candidate_strings(code):
        if not s or len(s) > 300 or not ("/" in s or s.startswith(("~", ".")) or "." in s):
            continue
        bases = [res.resolve(s, cmd.cwd).path]
        if not s.startswith(("/", "~")):  # `os.path.join(HOME, ".ssh", "id_rsa")`: the base is a variable, try the home dir
            bases.append(res.resolve(f"{ctx.home}/{s}", cmd.cwd).path)
        for path in filter(None, bases):
            kind = secret_kind(path, ctx.home)
            if kind:
                secrets.append(kind)
            prot = protected_kind(path, ctx)
            if prot and WRITEY.search(code):
                protected.append((prot, s))
    if secrets:
        if NETWORK.search(code):
            out.append(F("code.exfil", DENY, "exfiltration", f"{label}reads {secrets[0]} and talks to the network", cmd))
        else:
            out.append(F("code.secret-read", ASK, "secret", f"{label}reads {secrets[0]}", cmd))
    for (level, why), s in protected[:1]:
        out.append(F("code.tamper", level, "tamper", f"{label}writes to {why} (`{s}`)", cmd))
    return out


def inline_code(cmd: Command, lang: str) -> list[str]:
    flags = INLINE_FLAGS.get(lang, set())
    codes: list[str] = []
    argv = cmd.argv
    for i, a in enumerate(argv[1:], 1):
        is_flag = a in flags
        if not is_flag and lang in ("perl", "ruby") and a.startswith("-") and not a.startswith("--") and a[-1] in "eE" and len(a) <= 6:
            is_flag = True
        if is_flag and i + 1 < len(argv):
            codes.append(argv[i + 1])
    if lang == "deno" and len(argv) > 2 and argv[1] == "eval":
        codes.append(argv[2])
    return codes


def _read_script(path: str) -> Optional[str]:
    try:
        st = os.stat(path)
        if not os.path.isfile(path) or st.st_size > MAX_SCRIPT_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _script_arg(cmd: Command, lang: Optional[str]) -> Optional[str]:
    """The script file an interpreter or shell is asked to run, if any."""
    takes = {"-W", "-X", "-m", "-c", "-e", "-r", "-I", "-E"}
    skip = False
    for i, a in enumerate(cmd.argv[1:], 1):
        if skip:
            skip = False
            continue
        if a in takes and lang != "perl":
            if a in ("-m", "-c", "-e", "-r"):
                return None  # module or inline code, not a file
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return None


@rule("*")
def interpreters(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if not cmd.words or cmd.dyn(0):
        return []
    out: list[Finding] = []
    lang = _lang(cmd)
    name = cmd.name

    if lang == "python" and "-m" in cmd.argv[1:]:
        i = cmd.argv.index("-m")
        if i + 1 < len(cmd.argv) and cmd.argv[i + 1] in ("http.server", "SimpleHTTPServer"):
            out.append(F("network.http-server", ASK, "exposure", "`python -m http.server` serves this directory to anyone who can reach the port", cmd))

    if lang:
        for code in inline_code(cmd, lang):
            out += scan_code(code, cmd, ctx, res, f"inline {lang}", strict=True)
        for r in cmd.redirects:
            if r.op in ("<<", "<<-") and r.body:
                out += scan_code(r.body, cmd, ctx, res, f"{lang} here-doc", strict=True)
        script = _script_arg(cmd, lang)
        if script and not inline_code(cmd, lang):
            out += _check_script_file(script, cmd, ctx, res, lang)
    elif name in SHELLS or name in ("source", "."):
        script = _script_arg(cmd, None) if name in SHELLS else (cmd.argv[1] if len(cmd.argv) > 1 else None)
        if script and not any(a.startswith("-") and not a.startswith("--") and "c" in a[1:] for a in cmd.argv[1:]):
            out += _check_script_file(script, cmd, ctx, res, "shell")
    elif "/" in cmd.words[0].text and not cmd.words[0].dyn:
        out += _check_script_file(cmd.words[0].text, cmd, ctx, res, "shell", only_if_script=True)
    return out


def _check_script_file(arg: str, cmd: Command, ctx: Context, res: Resolver, lang: str, only_if_script: bool = False) -> list[Finding]:
    r = res.resolve(arg, cmd.cwd)
    if r.path is None:
        return []
    text = _read_script(r.path)
    if text is None:
        return []
    shell_like = lang == "shell" or text.startswith("#!") and re.match(r"#!\s*\S*(?:env\s+)?(?:ba|z|da|k)?sh\b", text.splitlines()[0] if text else "")
    if only_if_script and not (text.startswith("#!") or r.path.endswith((".sh", ".bash"))):
        return []
    name = posixpath.basename(r.path)
    if ctx.depth >= MAX_DEPTH:
        return [F("script.too-deep", ASK, "dynamic", f"{name} is part of a chain of scripts that is too deep to check", cmd)]
    if shell_like:
        from ..engine import analyze
        sub = analyze(text, Context(cwd=cmd.cwd or ctx.cwd, home=ctx.home, environ=ctx.environ, depth=ctx.depth + 1))
        return [Finding(f"script.{f.rule}", f.level, f.category, f"in {name}: {f.message}", cmd.raw) for f in sub.findings][:6]
    return scan_code(text, cmd, ctx, res, f"in {name}", strict=False)[:6]
