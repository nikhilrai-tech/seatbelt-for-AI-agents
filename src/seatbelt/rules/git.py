"""git rules: history rewrites, discarding work, deleting branches."""
from __future__ import annotations

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import Command, Word
from . import rule
from .opts import parse_words

ASK, DENY = Level.ASK, Level.DENY
PROTECTED_BRANCHES = {"main", "master", "develop", "development", "production", "prod", "release", "stable", "trunk"}
GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def _subcommand(words: list[Word]) -> tuple[str, list[Word]]:
    i = 0
    while i < len(words) and words[i].text.startswith("-"):
        i += 2 if words[i].text in GLOBAL_WITH_VALUE else 1
    return (words[i].text, words[i + 1:]) if i < len(words) else ("", [])


def _is_protected(ref: str) -> bool:
    name = ref.lstrip("+").split(":")[-1].removeprefix("refs/heads/")
    return name in PROTECTED_BRANCHES or name.startswith(("release/", "releases/", "hotfix/"))


@rule("git")
def git(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    sub, rest = _subcommand(cmd.words[1:])
    o = parse_words(rest)
    texts = [w.text for w in rest]
    out: list[Finding] = []

    if sub == "push":
        refs = [w.text for w in o.pos[1:]]  # first positional is the remote
        plus = [r for r in refs if r.startswith("+")]
        force = o.has("-f", "--force") or bool(plus)
        lease = o.has("--force-with-lease", "--force-if-includes") and not force
        deletes = o.has("-d", "--delete") or any(r.startswith(":") for r in refs)
        if o.has("--mirror"):
            out.append(F("git.push.mirror", DENY, "irreversible", "`git push --mirror` overwrites every ref on the remote", cmd))
        if force:
            hit = [r for r in refs if _is_protected(r)]
            out.append(F("git.push.force", DENY if hit else ASK, "irreversible",
                         "force-push rewrites remote history" + (f" of a protected branch ({', '.join(hit)})" if hit else
                                                                 " (other people's commits can be lost)"), cmd))
        elif lease:
            out.append(F("git.push.force-lease", ASK, "irreversible", "force-push (with lease) rewrites remote history", cmd))
        if deletes:
            hit = [r for r in refs if _is_protected(r.lstrip(":"))]
            out.append(F("git.push.delete", DENY if hit else ASK, "destructive",
                         "deletes a remote branch or tag" + (f" ({', '.join(hit)})" if hit else ""), cmd))
    elif sub == "reset":
        if o.has("--hard"):
            out.append(F("git.reset.hard", ASK, "destructive", "`git reset --hard` throws away uncommitted changes", cmd))
    elif sub == "clean":
        dry = o.has("-n", "--dry-run")
        if not dry and o.has("-f", "--force"):
            extra = " including ignored files (.env, build output)" if o.has("-x") else ""
            out.append(F("git.clean", ASK, "irreversible", f"`git clean -f` permanently deletes untracked files{extra}", cmd))
    elif sub == "checkout":
        if o.has("-f", "--force") or "." in texts or ("--" in texts and any(t in (".", "*") for t in texts)):
            out.append(F("git.checkout.discard", ASK, "destructive", "`git checkout` here discards uncommitted changes", cmd))
        elif o.has("-B"):
            out.append(F("git.checkout.reset-branch", ASK, "destructive", "`git checkout -B` resets an existing branch", cmd))
    elif sub in ("restore", "switch"):
        if sub == "restore" and not o.has("--staged") and ("." in texts or o.has("--worktree")):
            out.append(F("git.restore.discard", ASK, "destructive", "`git restore` discards uncommitted changes", cmd))
        if sub == "switch" and o.has("--discard-changes", "-f", "--force"):
            out.append(F("git.switch.discard", ASK, "destructive", "`git switch --discard-changes` throws away local changes", cmd))
    elif sub == "branch":
        if o.has("-D") or (o.has("-d") and o.has("-f", "--force")) or (o.has("--delete") and o.has("--force")):
            out.append(F("git.branch.delete", ASK, "destructive", "force-deleting a branch can lose unmerged commits", cmd))
    elif sub == "stash":
        if o.pos and o.pos[0].text in ("drop", "clear"):
            out.append(F("git.stash.drop", ASK, "irreversible", f"`git stash {o.pos[0].text}` discards saved work", cmd))
    elif sub in ("filter-branch", "filter-repo"):
        out.append(F("git.rewrite-history", ASK, "irreversible", f"`git {sub}` rewrites the entire history", cmd))
    elif sub == "reflog":
        if o.pos and o.pos[0].text in ("expire", "delete"):
            out.append(F("git.reflog.expire", ASK, "irreversible", "expiring the reflog removes the safety net for recovering lost commits", cmd))
    elif sub == "gc":
        if any(t.startswith("--prune=now") or t == "--aggressive" for t in texts):
            out.append(F("git.gc.prune", ASK, "irreversible", "`git gc --prune=now` permanently removes unreachable commits", cmd))
    elif sub == "update-ref":
        if o.has("-d"):
            out.append(F("git.update-ref.delete", ASK, "destructive", "`git update-ref -d` deletes a ref", cmd))
    elif sub == "worktree":
        if o.pos and o.pos[0].text == "remove" and o.has("-f", "--force"):
            out.append(F("git.worktree.remove", ASK, "destructive", "force-removing a worktree discards its changes", cmd))
    return out
