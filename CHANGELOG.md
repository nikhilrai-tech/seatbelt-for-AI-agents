# Changelog

## 0.1.3

- **Warns when the hook points into an ordinary virtual environment.** `seatbelt install` prints a warning and `seatbelt doctor` reports
  a warning: delete or recreate that environment and the hook stops working silently (Claude Code then runs commands unchecked).
  Tool installs (`pipx`, `uv tool`) are recognised as safe, and `seatbelt install` now prefers the stable launcher on PATH.

## 0.1.2

- The PyPI package is named **`seatbelt-guard`** (the command is still `seatbelt`). No code changes.

## 0.1.1

- **`seatbelt check --stdin [--quiet]`**: check every command on stdin, one per line (bash and zsh history files work) and get a
  summary. The fastest way to find false positives. Output is redacted, nothing is executed, previews are off.
- **`XDG_CONFIG_HOME`** is honoured for the user config; the tamper protection moves with it, so the agent cannot edit the config
  in the new location either. `seatbelt doctor` shows where the config would be.

## 0.1.0

First release. Zero dependencies, Python 3.11+. Licensed under **Apache-2.0** (the first commits of the repository were MIT; copies
obtained under MIT stay MIT).

- **Command analysis**: parses pipes, subshells, `sudo`/`env`/`xargs`, `bash -c`, `eval`, `ssh`, `kubectl exec`, here-docs, quoting and
  ANSI-C tricks; rules for the filesystem, `git` and the system; anything it cannot verify is an ASK.
- **Claude Code hook** (`PreToolUse`): answers only ask/deny, fails closed, never crashes; installer merges into `settings.json`
  and adds `onFailure: block` when Claude Code supports it; audit log with secrets redacted.
- **Secrets and prompt injection**: credential files, environment dumps, secret variables, secret -> network pipelines,
  `curl | sh`, decode-and-run, inline interpreter code, script files the agent wrote, tamper protection for the agent's own
  settings, seatbelt's config and audit log; the file tools (`Read`/`Write`/`Edit`...) are covered too.
- **Cloud and infra**: `aws`, `gcloud`/`gsutil`, `az`, PaaS CLIs, `gh`, `kubectl`/`helm`, `terraform`/`pulumi`/`cdk`, SQL,
  Redis/Mongo, migration tools, `docker`, package publishing. Production is detected, and irreversible actions there are denied.
- **Policy file**: allow/ask/deny rules, trusted hosts, extra production words. A project file can restrict but never permit.
- **Blast-radius preview** for deletions, measured in-process (seatbelt never runs `git` or other tools to find out).
- **Learn mode**: suggests narrow `allow` rules from the prompts you approved. Suggestions only.
- **`seatbelt doctor`**: checks the install and runs the installed hook as a live test; **`seatbelt demo`**: a guided tour.
- A fast path for `seatbelt hook` (about 60 ms per command), a security policy, issue templates and a contributing guide.
