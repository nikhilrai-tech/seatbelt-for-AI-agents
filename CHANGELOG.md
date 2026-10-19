# Changelog

## Unreleased

- **License changed from MIT to Apache-2.0** (explicit patent grant, more comfortable for companies). Copies already obtained under MIT stay MIT.

## 0.1.0

First release. Zero dependencies, Python 3.11+.

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
