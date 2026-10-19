"""Network rules: sending secrets out, exposing the machine."""
from __future__ import annotations

import re

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import Command, parse
from . import rule
from .opts import parse_words
from .secrets import REMOTE_SPEC, URL, secret_paths_in, secret_source_reason, secret_vars

ASK, DENY = Level.ASK, Level.DENY
FETCHERS = {"curl", "wget", "aria2c", "http", "https", "xh", "lwp-download"}
RAW_SINKS = {"nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp"}
SINKS = FETCHERS | RAW_SINKS | {"scp", "rsync", "ssh"}
CURL_VALUE_OPTS = {"-X", "--request", "-H", "--header", "-d", "--data", "--data-binary", "--data-raw", "--data-urlencode",
                   "--data-ascii", "-F", "--form", "--form-string", "-T", "--upload-file", "-o", "--output", "-u", "--user",
                   "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-w", "--write-out",
                   "-x", "--proxy", "--connect-timeout", "-m", "--max-time", "--retry", "--json", "-K", "--config", "--url"}
CURL_UPLOAD = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "-F", "--form",
               "--form-string", "-T", "--upload-file", "--json"}
EXPOSERS = {"ngrok", "cloudflared", "localtunnel", "lt", "bore", "frpc", "serveo"}


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def is_remote_transfer(cmd: Command) -> bool:
    return any(REMOTE_SPEC.match(a) and not a.startswith("-") for a in cmd.argv[1:])


def is_network_sink(cmd: Command) -> bool:
    n = cmd.name
    if n in ("scp", "rsync"):
        return is_remote_transfer(cmd)
    if n == "ssh":
        return cmd.pipe_in or any(r.op in ("<", "<<<") for r in cmd.redirects)
    return n in FETCHERS | RAW_SINKS


def sends_data(cmd: Command) -> bool:
    n = cmd.name
    o = parse_words(cmd.words[1:], CURL_VALUE_OPTS if n == "curl" else set())
    if n == "curl":
        method = (o.values.get("-X") or o.values.get("--request") or [""])[0].upper()
        return bool(o.flags & CURL_UPLOAD) or method in ("POST", "PUT", "PATCH", "DELETE")
    if n == "wget":
        return any(a.startswith(("--post-data", "--post-file", "--body-data", "--body-file")) or a in ("--method=POST", "--method=PUT")
                   for a in cmd.argv)
    if n in ("http", "https", "xh"):
        return cmd.pipe_in or any("=" in a or "@" in a for a in cmd.argv[2:] if not a.startswith("-"))
    return True  # nc, scp, rsync... transmit whatever they are given


def destination(cmd: Command) -> str:
    for a in cmd.argv[1:]:
        if URL.match(a):
            m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]+)", a)
            return m.group(1).split("@")[-1] if m else a
    for a in cmd.argv[1:]:
        if REMOTE_SPEC.match(a):
            return a.split(":")[0].split("@")[-1]
    rest = [a for a in cmd.argv[1:] if not a.startswith("-")]
    return rest[0] if rest else "a remote host"


@rule("curl", "wget", "aria2c", "http", "https", "xh", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "rsync", "ssh")
def network_sink(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if not is_network_sink(cmd):
        return []
    out: list[Finding] = []
    host = destination(cmd)
    uploads = sends_data(cmd)

    if uploads:
        for text, kind in secret_paths_in(cmd, ctx, res):
            out.append(F("exfil.secret-file", DENY, "exfiltration", f"sends {kind} (`{text}`) to {host}", cmd))
    for w in cmd.words:
        for sub in w.subs:
            for inner in parse(sub).commands:
                why = secret_source_reason(inner, ctx, res)
                if why:
                    out.append(F("exfil.secret-substitution", DENY, "exfiltration", f"puts {why} into a request to {host}", cmd))
    if cmd.words and any(secret_vars(w.text) for w in cmd.words[1:]) and not ctx.policy.trusts(host):
        v = next(v for w in cmd.words[1:] for v in secret_vars(w.text))
        out.append(F("exfil.secret-variable", ASK, "secret", f"sends the secret variable ${v} to {host}", cmd))
    return out


@rule(*EXPOSERS)
def expose(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    return [F("network.expose", ASK, "exposure", f"`{cmd.name}` makes a local service reachable from the internet", cmd)]


@rule("ssh")
def ssh_tunnel(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    o = parse_words(cmd.words[1:], {"-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S", "-w", "-W"})
    if o.has("-R"):
        return [F("network.ssh-reverse-tunnel", ASK, "exposure", "`ssh -R` opens a reverse tunnel: a remote host can reach back into this machine", cmd)]
    if any(v.startswith(("0.0.0.0:", "*:")) for v in o.values.get("-L", []) + o.values.get("-D", [])):
        return [F("network.ssh-open-forward", ASK, "exposure", "this SSH forward listens on all interfaces", cmd)]
    return []
