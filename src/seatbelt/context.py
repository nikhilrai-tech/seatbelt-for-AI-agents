from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Mapping, Optional

from .shell import Word

PROD_RE = re.compile(r"(?<![a-z0-9])(prod|production|prd)(?![a-z])", re.I)

SYSTEM_DIRS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin",
    "/srv", "/sys", "/usr", "/var", "/home", "/mnt", "/media", "/Users", "/System", "/Library", "/Applications",
    "/Volumes", "/private", "/snap", "/usr/bin", "/usr/lib", "/usr/local", "/usr/sbin", "/usr/share", "/var/lib",
    "/var/log",
}
HOME_SENSITIVE = (".ssh", ".aws", ".gnupg", ".kube", ".config", ".docker", ".azure", ".gcloud", ".npmrc", ".netrc")
SAFE_BUILD_DIRS = {
    "node_modules", "build", "dist", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv",
    "venv", ".next", ".nuxt", ".cache", "coverage", "htmlcov", ".tox", ".gradle", "out", ".turbo", ".parcel-cache",
    ".terraform", ".eggs", "tmp",
}
TEMP_DIRS = ("/tmp", "/var/tmp", "/var/folders", "/private/tmp")


@dataclass
class Context:
    cwd: str = field(default_factory=os.getcwd)
    home: str = field(default_factory=lambda: os.path.expanduser("~"))
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    headless: bool = False  # nobody can answer a prompt, so every ASK becomes a DENY

    def is_prod(self, *texts: str) -> bool:
        """True if the command or the environment it runs in looks like production."""
        for t in texts:
            if t and PROD_RE.search(t):
                return True
        for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "TF_WORKSPACE", "KUBE_CONTEXT", "CLOUDSDK_ACTIVE_CONFIG_NAME",
                    "APP_ENV", "ENVIRONMENT", "NODE_ENV", "RAILS_ENV", "DJANGO_ENV"):
            if PROD_RE.search(self.environ.get(key, "")):
                return True
        return False


@dataclass
class Resolved:
    path: str | None  # absolute, normalised; None if it can't be known statically
    glob: bool = False
    text: str = ""


class Resolver:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    def resolve(self, word: Word | str, cwd: Optional[str]) -> Resolved:
        text = word.text if isinstance(word, Word) else word
        has_glob = bool(word.glob) if isinstance(word, Word) else any(c in text for c in "*?[")
        p = text
        for var in ("${HOME}", "$HOME"):
            if p == var or p.startswith(var + "/"):
                p = self.ctx.home + p[len(var):]
        if "$" in p or "`" in p or "{}" in p:
            return Resolved(None, has_glob, text)
        if p == "~" or p.startswith("~/"):
            p = self.ctx.home + p[1:]
        elif p.startswith("~"):
            return Resolved(None, has_glob, text)
        if not p.startswith("/"):
            if cwd is None:
                return Resolved(None, has_glob, text)
            p = posixpath.join(cwd, p)
        return Resolved(posixpath.normpath(p) if p != "//" else "/", has_glob, text)

    def is_system(self, path: str) -> bool:
        home = self.ctx.home.rstrip("/") or "/"
        return path in SYSTEM_DIRS or path == home or home.startswith(path.rstrip("/") + "/")

    def within(self, path: str, base: str | None) -> bool:
        return bool(base) and (path == base or path.startswith(base.rstrip("/") + "/"))

    def in_temp(self, path: str) -> bool:
        return any(path.startswith(t + "/") for t in TEMP_DIRS)
