"""Helpers shared by the cloud, Kubernetes, IaC, database and container rules."""
from __future__ import annotations

import re
from typing import Optional

from ..context import Context
from ..model import Finding, Level
from ..shell import Command

ASK, DENY = Level.ASK, Level.DENY

READ_VERBS = {"describe", "list", "ls", "show", "get", "status", "info", "view", "search", "lookup", "inspect", "logs", "tail",
              "version", "help", "wait", "diff", "plan", "validate", "whoami", "check", "export", "history", "top", "events",
              "explain", "api-resources", "can-i", "read", "query", "scan", "head", "print", "test", "dry-run", "preview"}
DESTRUCTIVE_VERBS = {"delete", "remove", "rm", "destroy", "purge", "terminate", "deregister", "revoke", "detach", "disassociate",
                     "release", "cancel", "stop", "suspend", "wipe", "drop", "uninstall", "unlink", "erase", "reset", "kill",
                     "disable", "deprovision", "teardown", "prune", "empty", "close", "archive", "rb", "rmdir", "unpublish"}
MUTATING_VERBS = {"create", "update", "put", "set", "add", "apply", "deploy", "run", "start", "launch", "modify", "attach",
                  "associate", "enable", "tag", "untag", "patch", "replace", "edit", "scale", "resize", "restart", "rollout",
                  "upgrade", "install", "push", "publish", "import", "restore", "copy", "cp", "mv", "move", "sync", "invoke",
                  "send", "grant", "assign", "register", "rotate", "reboot", "promote", "migrate", "rollback", "pull", "build",
                  "annotate", "label", "taint", "cordon", "uncordon", "drain", "attach", "write", "insert", "upload"}


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def prod_signal(cmd: Command, ctx: Context, *extra: str) -> bool:
    return ctx.is_prod(" ".join(cmd.argv[1:]), *cmd.env.values(), *extra)


def is_dry_run(cmd: Command) -> bool:
    for a in cmd.argv[1:]:
        if a == "--dry-run" or a == "--dryrun" or (a.startswith("--dry-run=") and a.split("=", 1)[1] != "none"):
            return True
    return False


def loose_values(argv: list[str]) -> dict[str, list[str]]:
    """`--flag value` and `--flag=value` pairs, without knowing which flags take values (good enough for aws-style CLIs)."""
    out: dict[str, list[str]] = {}
    for i, a in enumerate(argv):
        if a.startswith("--") and "=" in a:
            k, _, v = a.partition("=")
            out.setdefault(k, []).append(v)
        elif a.startswith("--") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            out.setdefault(a, []).append(argv[i + 1])
    return out


def verb_class(token: str) -> Optional[str]:
    """read | destructive | mutating for a CLI verb such as `delete-db-instance`, `describe`, `put_item`."""
    t = token.lower().replace("_", "-")
    head = re.split(r"[-:.]", t, maxsplit=1)[0]
    if t in DESTRUCTIVE_VERBS or head in DESTRUCTIVE_VERBS or t.startswith(("delete", "remove", "destroy", "terminate", "purge")):
        return "destructive"
    if t in READ_VERBS or head in READ_VERBS:
        return "read"
    if t in MUTATING_VERBS or head in MUTATING_VERBS:
        return "mutating"
    return None


def classify_tokens(tokens: list[str]) -> tuple[Optional[str], int]:
    """First verb-like token decides: `gcloud compute instances describe delete-me` is a read, not a delete."""
    for i, t in enumerate(tokens):
        c = verb_class(t)
        if c:
            return c, i
    return None, -1


def has_path(tokens: list[str], *path: str) -> bool:
    """True if the tokens contain `path` in order (not necessarily next to each other)."""
    it = iter(tokens)
    return all(any(p == t for t in it) for p in path)


def level_for(prod: bool, irreversible: bool) -> Level:
    """Destructive things ask; irreversible things in production are refused."""
    return DENY if (prod and irreversible) else ASK
