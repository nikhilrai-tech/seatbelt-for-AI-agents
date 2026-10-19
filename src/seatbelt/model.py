from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .shell import Command


class Level(IntEnum):
    ALLOW = 0
    ASK = 1
    DENY = 2


@dataclass(frozen=True)
class Finding:
    rule: str  # stable id, e.g. "fs.rm.recursive"
    level: Level
    category: str  # destructive | irreversible | secret | exfiltration | dynamic | privilege | ...
    message: str
    command: str = ""  # the (simple) command this is about


@dataclass
class Verdict:
    level: Level
    findings: list[Finding] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)

    @property
    def reason(self) -> str:
        """One short paragraph suitable for showing to the agent and the human."""
        seen: list[str] = []
        for f in sorted(self.findings, key=lambda f: -int(f.level)):
            if f.message not in seen:
                seen.append(f.message)
        return "; ".join(seen[:4]) + (f" (+{len(seen) - 4} more)" if len(seen) > 4 else "")

    def to_dict(self) -> dict:
        return {"decision": self.level.name.lower(), "reason": self.reason,
                "findings": [{"rule": f.rule, "level": f.level.name.lower(), "category": f.category,
                              "message": f.message, "command": f.command} for f in self.findings]}
