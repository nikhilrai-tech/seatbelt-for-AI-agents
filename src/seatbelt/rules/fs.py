"""Filesystem rules: rm, find -delete, dd, mkfs and friends, chmod/chown -R, shred."""
from __future__ import annotations

import posixpath
import re

from ..context import HOME_SENSITIVE, SAFE_BUILD_DIRS, Context, Resolver
from ..model import Finding, Level
from ..shell import Command
from . import rule
from .opts import parse_words

ASK, DENY = Level.ASK, Level.DENY
DISK_DEVICE_PREFIXES = ("/dev/sd", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/mmcblk", "/dev/disk", "/dev/dm-", "/dev/mapper/")
HARMLESS_DEVICES = {"/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/random", "/dev/urandom"}


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def is_disk_device(path: str) -> bool:
    return path.startswith(DISK_DEVICE_PREFIXES)


def _delete_target(cmd: Command, ctx: Context, res: Resolver, word, recursive: bool, what: str, rule_id: str) -> list[Finding]:
    """Shared by rm and find -delete: judge deleting `word` (relative to the command's cwd)."""
    r = res.resolve(word, cmd.cwd)
    shown = word.text
    if r.path is None:
        if recursive:
            return [F(f"{rule_id}.unknown-target", ASK, "destructive",
                      f"{what} `{shown}`: the path is only known at runtime, so an empty variable could delete the wrong thing", cmd)]
        return []
    path = r.path
    if r.glob:
        base = posixpath.dirname(path) or "/"
        if res.is_system(base) or res.is_system(path):
            lvl = DENY if recursive else ASK
            return [F(f"{rule_id}.protected-glob", lvl, "irreversible",
                      f"{what} everything matching `{shown}` inside a system or home directory ({base})", cmd)]
        if recursive and not res.in_temp(path) and not (cmd.cwd and res.within(path, cmd.cwd)):
            return [F(f"{rule_id}.glob", ASK, "destructive", f"{what} everything matching `{shown}` outside the project", cmd)]
        if recursive and posixpath.basename(path) in ("*", ".*"):
            return [F(f"{rule_id}.glob", ASK, "destructive", f"{what} everything in {base}", cmd)]
        return []
    if res.is_system(path):
        if recursive:
            what_is = "your home directory" if path == res.ctx.home.rstrip("/") else "a system directory"
            return [F(f"{rule_id}.protected", DENY, "irreversible", f"{what} {what_is} ({path}): irreversible", cmd)]
        return [F(f"{rule_id}.system-path", ASK, "destructive", f"{what} a system path ({path})", cmd)]
    home = res.ctx.home.rstrip("/")
    if res.within(path, f"{home}/.ssh") or any(path == f"{home}/{d}" for d in HOME_SENSITIVE):
        return [F(f"{rule_id}.credentials", DENY if recursive else ASK, "irreversible",
                  f"{what} credentials or configuration ({path})", cmd)]
    if recursive:
        if cmd.cwd and (cmd.cwd == path or cmd.cwd.startswith(path.rstrip("/") + "/")):
            return [F(f"{rule_id}.cwd", ASK, "destructive", f"{what} the directory you are working in, or one of its parents ({path})", cmd)]
        if posixpath.basename(path) == ".git":
            return [F(f"{rule_id}.git-dir", ASK, "irreversible", f"{what} the git history ({path})", cmd)]
        # scratch space is fine, unless the project itself lives there (then it is the user's work)
        if res.in_temp(path) and not (cmd.cwd and res.in_temp(cmd.cwd)):
            return []
        if posixpath.basename(path) in SAFE_BUILD_DIRS and cmd.cwd and res.within(path, cmd.cwd):
            return []
        return [F(f"{rule_id}.recursive", ASK, "destructive", f"recursive delete of {path}", cmd)]
    if not ((res.in_temp(path) and not (cmd.cwd and res.in_temp(cmd.cwd))) or (cmd.cwd and res.within(path, cmd.cwd))):
        return [F(f"{rule_id}.outside-project", ASK, "destructive", f"{what} a file outside the project ({path})", cmd)]
    return []


@rule("rm", "unlink", "rmdir")
def rm(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    o = parse_words(cmd.words[1:])
    recursive = o.has("-r", "-R", "--recursive")
    out: list[Finding] = []
    if o.has("--no-preserve-root"):
        out.append(F("fs.rm.no-preserve-root", DENY, "irreversible", "`rm --no-preserve-root` turns off the safeguard against deleting /", cmd))
    if cmd.stdin_args and recursive and not o.pos:
        out.append(F("fs.rm.stdin-targets", ASK, "destructive", "recursive delete of paths produced at runtime (xargs / find -exec)", cmd))
    for w in o.pos:
        out += _delete_target(cmd, ctx, res, w, recursive, "deletes", "fs.rm")
    return out


@rule("find")
def find(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    argv = cmd.argv
    if "-delete" not in argv:
        return []
    roots = []
    for w in cmd.words[1:]:
        if w.text.startswith("-") or w.text in ("(", "!", ")"):
            break
        roots.append(w)
    roots = roots or [type(cmd.words[0])(".")]
    filtered = any(a in argv for a in ("-name", "-iname", "-path", "-ipath", "-regex", "-type", "-newer", "-mtime", "-mmin",
                                       "-empty", "-user", "-size", "-perm", "-atime", "-ctime"))
    out: list[Finding] = []
    for w in roots:
        found = _delete_target(cmd, ctx, res, w, True, "`find -delete` removes files under", "fs.find")
        if filtered:
            # `find . -name '*.pyc' -delete` is routine; only keep findings about protected places, and a name
            # filter means it is targeted, so ask rather than refuse
            found = [Finding(f.rule, ASK, f.category, f.message, f.command) for f in found
                     if f.level == DENY or f.rule.endswith(("protected", "credentials", "git-dir"))]
        out += found
    if not filtered and not out:
        out.append(F("fs.find.unfiltered-delete", ASK, "destructive", "`find -delete` with no name/type filter removes everything it finds", cmd))
    return out


@rule("dd")
def dd(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    for a in cmd.argv[1:]:
        if a.startswith("of="):
            target = a[3:]
            if target in HARMLESS_DEVICES:
                continue
            r = res.resolve(target, cmd.cwd)
            if r.path and is_disk_device(r.path):
                return [F("fs.dd.device", DENY, "irreversible", f"`dd` writing to a raw disk device ({r.path}) destroys its data", cmd)]
            if r.path is None:
                return [F("fs.dd.unknown-target", ASK, "destructive", "`dd` output path is only known at runtime", cmd)]
            import os
            if os.path.exists(r.path):
                return [F("fs.dd.overwrite", ASK, "destructive", f"`dd` overwrites the existing file {r.path}", cmd)]
    return []


@rule("mkfs", "mke2fs", "mkswap", "wipefs", "sfdisk", "parted", "gdisk", "sgdisk", "blkdiscard", "fdisk", "cfdisk")
def disk_tools(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    o = parse_words(cmd.words[1:])
    if cmd.name in ("fdisk", "sfdisk", "parted", "gdisk", "sgdisk") and o.has("-l", "--list", "-p", "--print", "-F"):
        return []
    return [F("fs.disk.format", DENY, "irreversible", f"`{cmd.name}` repartitions or formats disks and destroys their data", cmd)]


@rule("shred")
def shred(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    return [F("fs.shred", ASK, "irreversible", "`shred` overwrites files so they cannot be recovered", cmd)]


@rule("chmod", "chown", "chgrp")
def chmod(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    o = parse_words(cmd.words[1:])
    out: list[Finding] = []
    recursive = o.has("-R", "--recursive")
    args = [w for w in o.pos]
    mode = args[0].text if args else ""
    targets = args[1:]
    if recursive:
        for w in targets:
            r = res.resolve(w, cmd.cwd)
            if r.path is not None and res.is_system(r.path):
                out.append(F("fs.chmod.system", DENY, "destructive",
                             f"recursive `{cmd.name}` on {r.path} can break the whole system or lock you out", cmd))
        if cmd.name == "chmod" and mode in ("777", "a+rwx", "ugo+rwx", "o+w", "a+w", "666", "o+rwx"):
            out.append(F("fs.chmod.world-writable", ASK, "security", f"recursive `chmod {mode}` makes files writable by everyone", cmd))
    if cmd.name == "chmod" and (re.fullmatch(r"[2467][0-7]{3}", mode) or re.fullmatch(r"[ugoa]*[+=][rwxXt]*s[rwxXt]*", mode)):
        out.append(F("fs.chmod.setuid", ASK, "security", f"`chmod {mode}` sets the setuid/setgid bit", cmd))
    return out
