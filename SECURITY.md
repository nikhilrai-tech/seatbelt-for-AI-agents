# Security policy

seatbelt is a security tool, so a bug here can be a security bug. Thank you for looking.

## Supported versions

Only the latest release (currently 0.1.x) gets fixes.

## Reporting a vulnerability

Use GitHub's private reporting: **Security tab -> Report a vulnerability**
(https://github.com/nikhilrai-tech/seatbelt-for-AI-agents/security/advisories/new). Please do not open a public issue for
anything that could be used to harm users. This is a one-person project: expect an acknowledgement within about 7 days
and a fix or a clear answer within about 30. Reporters are credited unless they prefer not to be.

### What counts as a vulnerability

- **A fail-open**: a way for the hook to crash, hang or emit nothing for a command it should have checked.
- **A permission escalation**: a project file (`seatbelt.toml`) or any other repository content that makes seatbelt allow
  something, or that gets seatbelt to run code.
- **A bypass of a documented guarantee**: a command in a category the README says is `DENY` or `ASK` (secrets leaving the
  machine, production deletes, editing the guardrails, ...) that comes back `ALLOW`.
- **A leak**: secrets reaching the audit log, the prompt, or a file readable by others.
- **A path traversal or glob trick** that makes an `allow` rule match more than it says.

### What does not

- The documented limits (README, "What it cannot do"): values computed at runtime, what `make` or an MCP tool does
  internally, obfuscation beyond the supported decoders. These are known; improvements are welcome as normal issues.
- An agent or model misbehaving in a way no command reveals.
- A false positive (a harmless command that asks): please open a normal issue with the "false positive" template.

A plain false negative that cannot hurt anyone beyond what the limits already say is fine as a public issue with the
"bypass" template; when in doubt, report privately.

## The threat model, in short

seatbelt assumes the **agent's output and everything the agent reads are untrusted**: commands, scripts it writes, files
in the repository, `seatbelt.toml` in a cloned project, tool output. Only your user config
(`~/.config/seatbelt/config.toml`) is trusted. The design rules that follow:

- It **never executes** anything from the repository to analyse it (no `git`, no `kubectl`, no running scripts).
- It **fails closed**: an internal error, an unreadable input or an unverifiable command becomes an `ask`.
- It **never answers `allow`**; silence leaves the user's own permission rules in charge.
- A **project can restrict but never permit**; `allow` only lowers an `ask`, never a `deny`, and never applies to a
  command containing `..` or a variable.
- Secrets are **redacted before** anything is written to the audit log.

seatbelt is a guardrail, not a sandbox. For a hard guarantee run the agent in a container or VM and use seatbelt on top.

## Safe harbour

Good-faith research is welcome. Please test against your own machine and your own agent sessions, not against other
people's systems, and give a reasonable time to fix before publishing.
