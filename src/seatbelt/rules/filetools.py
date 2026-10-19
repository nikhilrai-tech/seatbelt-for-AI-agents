"""Claude Code's file tools (Read, Write, Edit, ...): same secret and tamper checks, without a shell."""
from __future__ import annotations

import posixpath

from ..context import Context, Resolver
from ..model import Finding, Level
from .secrets import secret_kind
from .tamper import protected_kind

READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
FILE_TOOLS = READ_TOOLS | WRITE_TOOLS


def target_path(tool_input: dict) -> str:
    for key in ("file_path", "notebook_path", "path"):
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def file_findings(tool: str, tool_input: dict, ctx: Context) -> list[Finding]:
    res = Resolver(ctx)
    path = target_path(tool_input)
    shown = f"{tool} {path}".strip()
    out: list[Finding] = []
    if not path:
        return out
    r = res.resolve(path, ctx.cwd)
    if r.path is None:
        return out
    if tool in READ_TOOLS:
        kind = secret_kind(r.path, ctx.home, glob=tool in ("Glob", "Grep") or r.glob)
        glob = tool_input.get("glob")
        if not kind and tool == "Grep" and isinstance(glob, str):
            kind = secret_kind("/" + posixpath.basename(glob), ctx.home)
        if kind:
            out.append(Finding("secret.read-tool", Level.ASK, "secret",
                               f"`{tool}` would read {kind} ({r.path}); its content would be sent to the model", shown))
    elif tool in WRITE_TOOLS:
        hit = protected_kind(r.path, ctx)
        if hit:
            level, what = hit
            msg = f"`{tool}` would change {what} ({r.path})"
            if level == Level.DENY:
                msg += ": agents must not edit their own guardrails or access paths; do it yourself if you mean it"
            out.append(Finding("tamper.protected-file", level, "tamper", msg, shown))
    return out
