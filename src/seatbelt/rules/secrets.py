"""Secrets: credential files, environment dumps and secret variables, plus the helpers the exfiltration rules share."""
from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Optional

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import Command
from . import rule
from .git import _subcommand

ASK = Level.ASK
URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
REMOTE_SPEC = re.compile(r"^[^/:\s=@]*@?[^/:\s=@]+:[^:]")

# relative to the home directory
HOME_SECRET_GLOBS = [
    (".aws/credentials", "AWS credentials"), (".aws/sso/cache/*", "AWS SSO tokens"), (".aws/cli/cache/*", "AWS CLI tokens"),
    (".ssh/id_*", "an SSH private key"), (".ssh/*_rsa", "an SSH private key"), (".ssh/*_ed25519", "an SSH private key"),
    (".ssh/*_ecdsa", "an SSH private key"), (".gnupg/*", "GPG keys"), (".kube/config", "kubeconfig (cluster credentials)"),
    (".docker/config.json", "Docker registry credentials"), (".netrc", "netrc credentials"), (".npmrc", "npm auth tokens"),
    (".pypirc", "PyPI credentials"), (".config/gh/hosts.yml", "GitHub CLI token"), (".git-credentials", "stored git credentials"),
    (".config/gcloud/*credentials*", "gcloud credentials"), (".config/gcloud/access_tokens.db", "gcloud tokens"),
    (".azure/accessTokens.json", "Azure tokens"), (".azure/msal_token_cache*", "Azure tokens"),
    (".terraform.d/credentials.tfrc.json", "Terraform Cloud token"), (".vault-token", "Vault token"), (".pgpass", "Postgres passwords"),
    (".my.cnf", "MySQL credentials"), (".config/doctl/config.yaml", "DigitalOcean token"), (".config/rclone/rclone.conf", "rclone credentials"),
    (".boto", "boto credentials"), (".s3cfg", "S3 credentials"), (".config/op/*", "1Password CLI data"),
    (".bash_history", "shell history (often contains secrets)"), (".zsh_history", "shell history (often contains secrets)"),
]
ABS_SECRET_GLOBS = [("/etc/shadow", "the password hashes"), ("/etc/gshadow", "group password hashes"), ("/etc/sudoers*", "sudo rules"),
                    ("/proc/*/environ", "a process environment (secrets)"), ("/etc/ssl/private/*", "TLS private keys")]
SECRET_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gcloud", ".config/gh", ".terraform.d")
NAME_GLOBS = [("*.pem", "a key/certificate file"), ("*.key", "a private key"), ("*_rsa", "an SSH private key"),
              ("*_ed25519", "an SSH private key"), ("*.p12", "a keystore"), ("*.pfx", "a keystore"), ("*.jks", "a keystore"),
              ("*.keystore", "a keystore"), ("*.tfstate", "Terraform state (contains secrets)"),
              ("*.tfstate.backup", "Terraform state (contains secrets)"), ("service-account*.json", "a cloud service-account key"),
              ("*serviceaccount*.json", "a cloud service-account key"), ("*credentials*.json", "a credentials file"),
              ("id_rsa", "an SSH private key"), ("id_ed25519", "an SSH private key"), (".htpasswd", "password hashes"),
              ("secrets.y*ml", "a secrets file"), ("secrets.json", "a secrets file")]
ENV_EXAMPLES = (".example", ".sample", ".template", ".dist", ".defaults", ".tpl")
NOT_SECRET_SUFFIXES = (".pub", ".crt", ".cer")
VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
NAME_HINTS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY", "APIKEY", "ACCESS_KEY", "AUTH_KEY", "SESSION_KEY")

# commands that merely mention a path without reading its content
HARMLESS = frozenset(
    "ls stat file test [ [[ cd pwd mkdir touch chmod chown chgrp echo printf which type command realpath basename dirname "
    "readlink du wc rm unlink shred rmdir export unset true false sleep seatbelt".split())
GIT_READS = {"add", "diff", "show", "blame", "grep", "cat-file", "archive", "bundle", "stash", "commit", "apply", "format-patch"}
ENV_DUMPERS = {"env", "printenv", "export", "declare", "typeset", "set", "compgen"}


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


def secret_kind(path: str, home: str, glob: bool = False) -> Optional[str]:
    """What kind of secret does this path hold? None if it is not one."""
    home = home.rstrip("/")
    base = posixpath.basename(path)
    if base.endswith(NOT_SECRET_SUFFIXES):
        return None
    if base == ".env" or (base.startswith(".env.") and not base.endswith(ENV_EXAMPLES)):
        return "an environment file (.env)"
    if path.startswith(home + "/"):
        rel = path[len(home) + 1:]
        for pat, label in HOME_SECRET_GLOBS:
            if fnmatch.fnmatchcase(rel, pat):
                return label
        for d in SECRET_DIRS:
            if rel == d or (glob and posixpath.dirname(rel) == d):
                return f"the credential directory ~/{d}"
    for pat, label in ABS_SECRET_GLOBS:
        if fnmatch.fnmatchcase(path, pat):
            return label
    for pat, label in NAME_GLOBS:
        if fnmatch.fnmatchcase(base, pat):
            return label
    return None


def secret_vars(text: str) -> list[str]:
    out = []
    for name in VAR_REF.findall(text):
        up = name.upper()
        if up.endswith("_SOCK") or up.endswith("_PATH") or up.endswith("_FILE"):
            continue
        if any(w in up for w in NAME_HINTS) or up in ("GITHUB_PAT", "GH_TOKEN", "NPM_TOKEN", "PGPASSWORD", "MYSQL_PWD"):
            out.append(name)
    return out


def _candidates(text: str) -> list[str]:
    """A word may carry a path after `=` or `@` (--env-file=.env, -d @.env, -F f=@key)."""
    out = [text]
    for sep in ("=", "@"):
        if sep in text:
            out.append(text.split(sep, 1)[1])
    if text.startswith("@"):
        out.append(text[1:])
    return [c for c in out if c]


def secret_paths_in(cmd: Command, ctx: Context, res: Resolver) -> list[tuple[str, str]]:
    """(shown text, kind) for every argument or input redirect of `cmd` that names a secret file."""
    found: list[tuple[str, str]] = []
    texts = [(w.text, w.glob) for w in cmd.words[1:]] + [(r.target, False) for r in cmd.redirects if r.op in ("<", "<<<", "<>")]
    for text, glob in texts:
        if URL.match(text) or REMOTE_SPEC.match(text):  # https://host/.env is a download, host:/path is a remote file
            continue
        for cand in _candidates(text):
            r = res.resolve(cand, cmd.cwd)
            if r.path:
                kind = secret_kind(r.path, ctx.home, glob or r.glob)
                if kind:
                    found.append((text, kind))
                    break
    return found


def dumps_environment(cmd: Command) -> bool:
    n, args = cmd.name, cmd.argv[1:]
    if n == "env":
        return all(a.startswith("-") or "=" in a for a in args)  # no command to run, so it just prints everything
    if n == "printenv":
        return not [a for a in args if not a.startswith("-")]
    if n in ("export", "declare", "typeset"):
        return any(a in ("-p", "-x", "-xp", "-px") for a in args) and not [a for a in args if not a.startswith("-")]
    if n == "set":
        return not args
    if n == "compgen":
        return "-e" in args or "-v" in args
    return False


def secret_source_reason(cmd: Command, ctx: Context, res: Resolver) -> Optional[str]:
    """Why this command's output would contain secrets (used to spot secret -> network pipelines)."""
    if cmd.name in HARMLESS - {"echo", "printf"}:
        return None
    hits = secret_paths_in(cmd, ctx, res)
    if hits:
        return hits[0][1]
    if dumps_environment(cmd):
        return "the environment variables"
    if cmd.name in ("echo", "printf") and any(secret_vars(w.text) for w in cmd.words[1:]):
        return "a secret variable"
    if cmd.name == "git" and _subcommand(cmd.words[1:])[0] == "config" and any(a in ("--get-regexp", "--list", "-l") for a in cmd.argv):
        return "git config (may hold credentials)"
    if cmd.name == "aws" and "configure" in cmd.argv and "get" in cmd.argv:
        return "AWS credentials"
    if cmd.name == "gpg" and any("secret-key" in a for a in cmd.argv):
        return "GPG secret keys"
    return None


@rule("*")
def secret_access(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    name = cmd.name
    out: list[Finding] = []
    if name in ENV_DUMPERS and dumps_environment(cmd):
        out.append(F("secret.env-dump", ASK, "secret", f"`{name}` prints every environment variable, which often include secrets", cmd))
    if name in ("echo", "printf"):
        names = sorted({v for w in cmd.words[1:] for v in secret_vars(w.text)})
        if names:
            out.append(F("secret.print-var", ASK, "secret", f"prints the secret variable ${names[0]}", cmd))
    if name in HARMLESS:
        return out
    if name == "git" and _subcommand(cmd.words[1:])[0] not in GIT_READS:
        return out
    for text, kind in secret_paths_in(cmd, ctx, res):
        out.append(F("secret.read", ASK, "secret", f"`{name}` reads or copies {kind} (`{text}`)", cmd))
        break
    return out


