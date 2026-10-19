# What I learned about Claude Code hooks while building this

Notes from reading the hooks reference and then testing against a real Claude Code session (2.1.302, Linux). Anything
marked **verified** was observed end to end; the rest is from the documentation.

## The contract

A `PreToolUse` hook gets one JSON object on stdin:

```json
{"session_id": "...", "cwd": "/home/me/project", "permission_mode": "default", "hook_event_name": "PreToolUse",
 "tool_name": "Bash", "tool_input": {"command": "npm test", "description": "...", "timeout": 120000}, "tool_use_id": "..."}
```

It decides by printing one JSON object and exiting 0:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}
```

`permissionDecision` is `allow`, `deny`, `ask` (show the normal prompt) or `defer` (non-interactive only). With several
hooks the precedence is `deny > defer > ask > allow`. The shell tools are named `Bash` and `PowerShell`, so match both
(`"matcher": "Bash|PowerShell"`).

## The three things that shape the design

**1. A broken hook fails open.** Exit 2 blocks. Any *other* non-zero exit is a "non-blocking error": the tool call still
runs. A timed-out hook does not block either. So the largest risk of a guardrail is the guardrail failing: a crash, a
missing binary, a broken virtualenv, all silently let the command through. What seatbelt does about it:

- the engine is fuzz-tested to never raise (`tests/test_rules.py`), and `hook.handle` answers `ask` on any exception or
  unreadable input instead of crashing;
- `seatbelt install` adds `"onFailure": "block"` when the installed Claude Code is new enough (2.1.295+), which turns a
  failed or missing hook into a block. It checks `claude --version` rather than guessing, because an unknown key in
  `settings.json` could break the user's configuration on older versions.

**2. `allow` is not neutral.** `allow` skips the permission prompt (deny and ask rules still apply). A guardrail that
answers `allow` for "looks safe" would silently remove the user's own prompts. seatbelt never answers `allow`: safe
commands get *silence* (exit 0, no output), which leaves the user's permission rules in charge. Only `ask` and `deny` are
ever emitted.

**3. stdout is the protocol.** If anything other than the JSON object reaches stdout, the decision is lost. Everything
else goes to stderr or the audit file, and a test runs the real process and checks stdout byte for byte.

## Verified behaviour in a real session

| What the agent tried | seatbelt said | What happened |
|---|---|---|
| `git push --force origin main` | deny | The tool call never ran. The agent quoted the reason back to the user and did not try a workaround. |
| `rm -rf src` (project outside `/tmp`) | ask | In non-interactive mode (`claude -p`) nobody can answer a prompt, so the call was blocked and the reason was shown. Use `--headless` to make that explicit. |
| `ls` | silence | Ran normally. |

The deny message is written for the *agent*: it says not to retry with a different spelling and to ask the user instead.
Without that sentence, an agent that is blocked tends to look for another way to do the same thing.

## A bug the real session found

The first end-to-end test used a project directory under `/tmp`, and `rm -rf src` was allowed, because seatbelt treats
anything under `/tmp` as scratch space. A project that happens to live in `/tmp` is still the user's work. The scratch
exemption now applies only when the working directory is not itself inside a temp directory.

## Two more things the real session taught me

**The model is a second guardrail, and it is not the one under test.** When I tried to demonstrate an exfiltration
(`cat .env | curl -d @- ...`) and a planted git hook, Claude declined on its own before seatbelt was ever consulted. That is
good, but it means a test only exercises seatbelt if the request looks like ordinary work. The tests that count were the
ones phrased the way a real task or a real injection would be phrased ("call this API with my token", "install a
pre-commit hook with a small script").

**Static checks lose to string building.** The agent's script wrote `.git/hooks/pre-commit` via
`os.path.join(".git", "hooks", "pre-commit")`, so no string literal held the full path and the first version of the script
scanner let it through. Following common ways of assembling a path from constants closed that hole (and a regression test
uses the exact script); computing a path at runtime is still out of reach, which is why the README has a limits section.

| What the agent tried | seatbelt | Result |
|---|---|---|
| `Read .env` | ask | blocked in non-interactive mode, reason shown, agent did not try `cat` instead |
| `curl -H "Authorization: Bearer $GITHUB_TOKEN" ...` | ask | blocked with "sends the secret variable $GITHUB_TOKEN to host" |
| `python3 hook.py` (writes `.git/hooks/pre-commit`) | ask | blocked, and the agent read the reason from inside the script check |

## A bypass the policy file had

A project `seatbelt.toml` denied `npm run deploy*`. In a real session the agent was blocked on `npm run deploy`, but
`npm run --silent deploy` ran: a glob over literal text is trivially dodged by one more flag. `deny` and `ask` rules are
now also matched with the flags removed. `allow` rules stay literal on purpose: matching them loosely would let
`git push -f origin feature/x` through an allow written for `git push origin feature/*`. A flag that takes a value leaves
the value behind (`npm --prefix app run deploy`), so the README tells people to write `npm * run deploy*`.

## The preview nearly made the guardrail slow

The first version measured every ASK *and* DENY. The test suite went from 3 s to 56 s: `rm -rf /*` has dozens of glob
matches, each measured with its own budget, and a fuzz test with random `rm` targets walked the disk thousands of times.
In a hook that is not a test-speed problem, it is a user-facing delay on exactly the commands people are about to
approve. The fixes: skip DENY (nothing left to decide), share one budget across all the paths of a command line, and say
"not counted" when the budget runs out instead of showing nothing, which would read as "harmless".

## Which events fire when (measured, Claude Code 2.1.302)

To let learn mode know what a human approved, I logged every hook event for three tool calls in a scratch project:

| Call | Events, in order |
|---|---|
| `echo ok-one` (ran fine) | `PreToolUse` -> `PostToolUse` (`tool_response` has `stdout`, `stderr`, `interrupted`, ...) |
| `ls /no-such-dir` (exit 2) | `PreToolUse` -> `PostToolUseFailure` (not `PostToolUse`) |
| a command a hook denied | `PreToolUse` only. No Post event, and no `PermissionDenied` event either |

The `tool_use_id` is identical in the Pre and Post event of one call, so it is the join key. "A Post event of either kind
followed an ASK" is the only reliable signal that the human said yes; the absence of one means declined, failed to start,
or not answered yet (so recent unanswered asks are treated as pending, not declined).

## A glob that is wider than it looks

Learn mode suggests patterns like `rm -rf build/*`. In `fnmatch`, `*` also matches `..` and `$TARGET`, so that rule would
have waved through `rm -rf build/../../data`. `allow` rules now never apply to a command containing a `..` path
component or a `$VAR`/`$(...)`, with a regression test.
