"""Infrastructure as code: terraform/tofu/terragrunt, pulumi, cdk, serverless, ansible."""
from __future__ import annotations

import posixpath
from pathlib import Path

from ..context import Context, Resolver
from ..model import Finding
from ..shell import Command
from . import rule
from .common import ASK, DENY, F, level_for

TF_VALUE_OPTS = {"-var", "-var-file", "-target", "-state", "-out", "-parallelism", "-lock-timeout", "-backend-config", "-replace"}


def _tf_args(argv: list[str]) -> tuple[list[str], set[str]]:
    """Terraform uses single-dash long flags (-auto-approve), so split by hand: (positionals, flag names)."""
    tokens: list[str] = []
    flags: set[str] = set()
    skip = False
    for a in argv:
        if skip:
            skip = False
        elif a.startswith("-") and len(a) > 1:
            flags.add(a.split("=", 1)[0])
            skip = a in TF_VALUE_OPTS
        else:
            tokens.append(a)
    return tokens, flags


def _workspace(cmd: Command, ctx: Context, chdir: str) -> str:
    ws = ctx.environ.get("TF_WORKSPACE", "")
    if ws:
        return ws
    base = chdir or cmd.cwd or ctx.cwd
    try:
        p = Path(base) / ".terraform" / "environment"
        if p.is_file() and p.stat().st_size < 256:
            return p.read_text().strip()
    except OSError:
        pass
    return ""


@rule("terraform", "tofu", "terragrunt")
def terraform(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    chdir = next((a.split("=", 1)[1] for a in cmd.argv[1:] if a.startswith("-chdir=")), "")
    argv = [a for a in cmd.argv[1:] if not a.startswith("-chdir=")]
    tokens, flags = _tf_args(argv)
    sub = tokens[0] if tokens else ""
    ws = _workspace(cmd, ctx, chdir)
    dirs = " ".join(p for p in (posixpath.basename(chdir or cmd.cwd or ""), posixpath.basename(posixpath.dirname(chdir or cmd.cwd or ""))) if p)
    prod = ctx.is_prod(ws, " ".join(argv), dirs, *cmd.env.values())
    where = " on PRODUCTION" if prod else ""
    destroying = sub in ("destroy", "destroy-all") or (sub in ("apply", "run-all", "apply-all") and ("-destroy" in flags or "destroy" in tokens))
    out: list[Finding] = []
    if destroying:
        out.append(F("iac.destroy", level_for(prod, True), "irreversible", f"`{cmd.name} destroy` tears down infrastructure{where}", cmd))
    elif sub in ("apply", "apply-all") or (sub == "run-all" and "apply" in tokens):
        auto = "-auto-approve" in flags
        if auto:
            out.append(F("iac.auto-approve", DENY if prod else ASK, "production" if prod else "destructive",
                         f"`{cmd.name} apply -auto-approve` changes infrastructure without anyone reading the plan{where}", cmd))
        elif prod:
            out.append(F("iac.prod-apply", ASK, "production", f"`{cmd.name} apply` changes infrastructure{where}", cmd))
    elif sub == "state" and len(tokens) > 1 and tokens[1] in ("rm", "mv", "push", "replace-provider"):
        out.append(F("iac.state", ASK, "destructive", f"`{cmd.name} state {tokens[1]}` edits the state file; resources can be orphaned or recreated", cmd))
    elif sub == "state" and len(tokens) > 1 and tokens[1] == "pull":
        out.append(F("iac.state-pull", ASK, "secret", "the state file contains secrets in plain text", cmd))
    elif sub in ("force-unlock", "taint", "untaint") or (sub == "workspace" and len(tokens) > 1 and tokens[1] == "delete"):
        out.append(F("iac.state-op", ASK, "destructive", f"`{cmd.name} {' '.join(tokens[:2])}` alters state or locks{where}", cmd))
    elif sub == "import" and prod:
        out.append(F("iac.prod-import", ASK, "production", f"`{cmd.name} import` changes state{where}", cmd))
    return out


@rule("pulumi", "cdk", "serverless", "sls", "sam", "cdktf")
def other_iac(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    tokens = [a for a in cmd.argv[1:] if not a.startswith("-")]
    flags = set(cmd.argv[1:])
    stage = " ".join(cmd.argv[1:]) + " " + " ".join(cmd.env.values())
    prod = ctx.is_prod(stage)
    where = " on PRODUCTION" if prod else ""
    sub = tokens[0] if tokens else ""
    if sub in ("destroy", "remove", "delete") or (cmd.name == "pulumi" and sub == "stack" and "rm" in tokens):
        return [F("iac.destroy", level_for(prod, True), "irreversible", f"`{cmd.name} {sub}` tears down a stack{where}", cmd)]
    if (sub in ("up", "deploy") and ("--yes" in flags or "-y" in flags or "never" in cmd.argv or "--require-approval=never" in flags)) or \
            (sub == "up" and "--skip-preview" in flags):
        return [F("iac.auto-approve", DENY if prod else ASK, "production" if prod else "destructive",
                  f"`{cmd.name} {sub}` without an approval step{where}", cmd)]
    if sub in ("up", "deploy") and prod:
        return [F("iac.prod-apply", ASK, "production", f"`{cmd.name} {sub}` changes infrastructure{where}", cmd)]
    return []


@rule("ansible-playbook", "ansible")
def ansible(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if any(a in ("--check", "-C", "--syntax-check", "--list-hosts") for a in cmd.argv):
        return []
    if ctx.is_prod(" ".join(cmd.argv[1:]), *cmd.env.values()):
        return [F("iac.ansible-prod", ASK, "production", "runs against PRODUCTION hosts without --check", cmd)]
    return []
