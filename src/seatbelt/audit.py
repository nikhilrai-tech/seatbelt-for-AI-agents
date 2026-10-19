"""Append-only audit log of everything the agent ran, with secrets redacted before anything is written."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

MAX_BYTES = 10 * 1024 * 1024

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "***PRIVATE KEY***"),
    (re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), "***AWS-KEY***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "***GITHUB-TOKEN***"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "***GITHUB-TOKEN***"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "***API-KEY***"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "***SLACK-TOKEN***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "***JWT***"),
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)\S+"), r"\1***"),
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)"), r"\1***\2"),
    (re.compile(r"(?i)(\b[\w.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|credential)[\w.-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1***"),
    (re.compile(r"(?i)(--(?:password|passwd|token|secret|api-key)[= ])\S+"), r"\1***"),
    (re.compile(r"(\s-p)(?=\S{4,})\S+"), r"\1***"),  # mysql -pPASSWORD
]


def redact(text: str) -> str:
    for rx, repl in _REDACTIONS:
        text = rx.sub(repl, text)
    return text


def default_path() -> Path:
    override = os.environ.get("SEATBELT_AUDIT_LOG")
    if override:
        return Path(override)
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "seatbelt" / "audit.jsonl"


class AuditLog:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_path()

    @staticmethod
    def enabled() -> bool:
        return os.environ.get("SEATBELT_AUDIT", "on").lower() not in ("off", "0", "false", "no")

    def record(self, entry: dict) -> None:
        """Never raises: a logging problem must not change what the hook decides."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.path.exists() and self.path.stat().st_size > MAX_BYTES:
                self.path.replace(self.path.with_suffix(".jsonl.1"))
            entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **entry}
            if "command" in entry:
                entry["command"] = redact(str(entry["command"]))[:4000]
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def read(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
