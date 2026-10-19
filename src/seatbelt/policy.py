"""User policy (TOML). Lets people tune seatbelt without it ever being tunable *by the project the agent works in*.

Two sources, with different trust:
  * user config  (SEATBELT_CONFIG, or ~/.config/seatbelt/config.toml): may allow, ask, deny, trust hosts, add prod words
  * project file (seatbelt.toml / .seatbelt.toml in the working directory or a parent): may only ask, deny, add prod
    words. A cloned repository must never be able to grant itself permissions, so `allow` and `trusted_hosts` in a
    project file are ignored (and reported).

Example:

    headless = false
    prod_patterns = ["live", "eu-prod"]
    trusted_hosts = ["api.github.com", "*.mycompany.com"]

    [[allow]]
    command = "git push origin feature/*"
    reason = "agents may push feature branches"

    [[deny]]
    command = "kubectl * --context=prod*"
    reason = "no agent touches the prod cluster"

`command` is a glob matched against the simple command with its arguments joined by single spaces. `deny` and `ask`
rules also match with the flags removed (`npm run --silent deploy` is caught by `npm run deploy*`), so they are hard
to dodge by adding an option. `allow` rules are deliberately literal: otherwise `git push -f origin feature/x` would
slip through an allow for `git push origin feature/*`. `allow` only lowers an ASK to nothing; it can never lower a DENY
or an ask about tampering with the guardrails.
"""
from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

PROJECT_FILES = ("seatbelt.toml", ".seatbelt.toml")


@dataclass
class PolicyRule:
    pattern: str
    reason: str = ""
    source: str = ""


@dataclass
class Policy:
    allow: list[PolicyRule] = field(default_factory=list)
    ask: list[PolicyRule] = field(default_factory=list)
    deny: list[PolicyRule] = field(default_factory=list)
    trusted_hosts: list[str] = field(default_factory=list)
    prod_patterns: list[str] = field(default_factory=list)
    headless: Optional[bool] = None
    warnings: list[str] = field(default_factory=list)
    error: Optional[str] = None
    sources: list[str] = field(default_factory=list)

    @staticmethod
    def match(rules: list[PolicyRule], text: str) -> Optional[PolicyRule]:
        return next((r for r in rules if fnmatch.fnmatchcase(text, r.pattern)), None)

    def trusts(self, host: str) -> bool:
        host = host.lower().split(":")[0]
        return any(fnmatch.fnmatchcase(host, h.lower()) for h in self.trusted_hosts)


def _rules(items, source: str, warnings: list[str], kind: str) -> list[PolicyRule]:
    out = []
    for item in items or []:
        if isinstance(item, dict) and isinstance(item.get("command"), str) and item["command"].strip():
            out.append(PolicyRule(item["command"].strip(), str(item.get("reason", "")), source))
        else:
            warnings.append(f"{source}: a [[{kind}]] entry needs a `command` string")
    return out


def _merge(policy: Policy, data: dict, source: str, trusted: bool) -> None:
    policy.sources.append(source)
    policy.ask += _rules(data.get("ask"), source, policy.warnings, "ask")
    policy.deny += _rules(data.get("deny"), source, policy.warnings, "deny")
    words = data.get("prod_patterns") or []
    policy.prod_patterns += [str(w) for w in words if isinstance(w, str) and w.strip()]
    if trusted:
        policy.allow += _rules(data.get("allow"), source, policy.warnings, "allow")
        policy.trusted_hosts += [str(h) for h in data.get("trusted_hosts") or [] if isinstance(h, str)]
        if isinstance(data.get("headless"), bool):
            policy.headless = data["headless"]
    else:
        if data.get("allow") or data.get("trusted_hosts"):
            policy.warnings.append(f"{source}: `allow` and `trusted_hosts` are ignored in a project file "
                                   f"(a repository cannot grant itself permissions); put them in your user config")
        if data.get("headless") is True:
            policy.headless = True  # tightening is allowed


def _read(path: Path, policy: Policy, trusted: bool) -> None:
    try:
        if path.stat().st_size > 256 * 1024:
            policy.error = f"{path} is too large to be a seatbelt config"
            return
        _merge(policy, tomllib.loads(path.read_text(encoding="utf-8")), str(path), trusted)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        policy.error = f"{path} could not be read ({type(exc).__name__}: {exc})"


def config_dir(home: str, environ: Mapping[str, str]) -> Path:
    """`$XDG_CONFIG_HOME/seatbelt` when set to an absolute path (as the XDG spec says), else `~/.config/seatbelt`."""
    xdg = environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg.startswith("/") else Path(home) / ".config"
    return base / "seatbelt"


def user_config_path(home: str, environ: Mapping[str, str]) -> Path:
    override = environ.get("SEATBELT_CONFIG")
    return Path(override) if override else config_dir(home, environ) / "config.toml"


def find_project_file(cwd: str, home: str) -> Optional[Path]:
    here = Path(cwd).resolve() if cwd else None
    stop = Path(home).resolve()
    for d in ([here] + list(here.parents)) if here else []:
        for name in PROJECT_FILES:
            if (d / name).is_file():
                return d / name
        if d == stop or d == Path(d.anchor):
            break
    return None


def load(cwd: str, home: Optional[str] = None, environ: Optional[Mapping[str, str]] = None) -> Policy:
    home = home or os.path.expanduser("~")
    environ = environ if environ is not None else os.environ
    policy = Policy()
    user = user_config_path(home, environ)
    if user.is_file():
        _read(user, policy, trusted=True)
    project = find_project_file(cwd, home)
    if project and not (policy.error):
        _read(project, policy, trusted=False)
    return policy
