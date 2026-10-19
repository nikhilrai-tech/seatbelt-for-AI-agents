# Contributing

Thanks for helping. The most useful contributions are **a command seatbelt gets wrong** (in either direction) and **a rule
for a tool it does not know yet**.

## Setup

```bash
git clone https://github.com/nikhilrai-tech/seatbelt-for-AI-agents && cd seatbelt-for-AI-agents
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest -q && .venv/bin/python -m pyflakes src tests
.venv/bin/seatbelt demo
```

Python 3.11+, no runtime dependencies (keep it that way).

## What a good change looks like

seatbelt lives or dies on two numbers: how few dangerous commands get through, and how few harmless ones are interrupted.
A rule that interrupts everyday work gets switched off, so **every change is judged in both directions**:

1. **The rule**, in `src/seatbelt/rules/` (`@rule("name")`, returns findings). Look at `rules/git.py` for a small one.
2. **Corpus lines** in `examples/commands.txt` (`EXPECTED<TAB>command`): the dangerous forms *and* at least two everyday
   neighbours that must stay `ALLOW`. The corpus is the regression suite; it runs as tests.
3. **A false-positive guard**: add the common harmless commands of that tool to the "everyday commands stay quiet" lists in
   `tests/test_secrets_exfil.py` or `tests/test_cloud.py`.
4. A line in the README table if a user would notice.

## Ground rules

- **Fail closed.** If it cannot tell what a command does, it asks; it never guesses `allow`.
- **Never execute anything from the project being checked.** No `git`, no `kubectl`, no running scripts; read files
  in-process, regular files only, size-capped (see `preview.py` for why).
- **Tests are deterministic**: no real network, no real cloud, no dependence on the machine's home directory or
  environment (use `Context(cwd=..., home=..., environ={})`).
- **No real secrets or identifiers in fixtures.** Build key-shaped samples at runtime (`"AKIA" + "..."`) so secret scanners
  and readers see nothing real. No real hostnames, account ids or people's names.
- `allow` can only lower an `ask`; keep it that way.

## Reporting a wrong verdict

Run `seatbelt check --json '<command>'` and paste the output into the matching issue template. Remove anything private
from the command first. A suspected vulnerability goes through SECURITY.md, not a public issue.

## Reverse-engineering notes

If you find new Claude Code (or other agent) hook behaviour, add what you measured and how to `docs/claude-code-hooks.md`.
Say which version you saw it on.
