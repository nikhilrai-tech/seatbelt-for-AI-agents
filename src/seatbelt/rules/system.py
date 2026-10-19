"""System-level rules: privilege escalation, power, processes, services."""
from __future__ import annotations

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import Command
from . import rule
from .opts import parse_words

ASK, DENY = Level.ASK, Level.DENY


def F(rule_id: str, level: Level, category: str, message: str, cmd: Command) -> Finding:
    return Finding(rule_id, level, category, message, cmd.raw)


@rule("sudo", "doas", "su", "pkexec")
def privilege(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    return [F("system.privilege", ASK, "privilege", f"`{cmd.name}` runs the command with elevated privileges", cmd)]


@rule("shutdown", "reboot", "halt", "poweroff", "init", "telinit")
def power(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if cmd.name in ("init", "telinit") and not any(a in ("0", "6") for a in cmd.argv[1:]):
        return []
    if cmd.name == "shutdown" and any(a in ("-c",) for a in cmd.argv[1:]):
        return []
    return [F("system.power", ASK, "destructive", f"`{cmd.name}` stops or restarts the machine", cmd)]


@rule("kill", "killall", "pkill")
def kill(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    tokens = cmd.argv[1:]
    pids = [w.text for w in parse_words(cmd.words[1:]).pos]
    if cmd.name == "kill":
        # `kill 1` stops init; `kill -9 -1` signals every process you can signal
        if "1" in pids or ("-1" in tokens and not any(p.isdigit() for p in pids)):
            return [F("system.kill.all", DENY, "destructive", "this `kill` takes down pid 1 or every process", cmd)]
    elif any(a in ("*", ".", ".*") for a in pids):
        return [F("system.kill.pattern", ASK, "destructive", f"`{cmd.name}` with a catch-all pattern kills unrelated processes", cmd)]
    return []


@rule("systemctl", "service", "launchctl")
def services(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    words = [a for a in cmd.argv[1:] if not a.startswith("-")]
    verbs = {"stop", "disable", "mask", "kill", "isolate", "poweroff", "reboot", "halt", "unload", "remove", "bootout"}
    hit = [w for w in words if w in verbs]
    if hit:
        return [F("system.service", ASK, "destructive", f"`{cmd.name} {hit[0]}` stops or disables a service", cmd)]
    return []


@rule("crontab")
def crontab(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if "-r" in cmd.argv[1:]:
        return [F("system.crontab.remove", ASK, "destructive", "`crontab -r` deletes every scheduled job without asking", cmd)]
    return []


@rule("iptables", "ip6tables", "nft", "ufw")
def firewall(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    a = cmd.argv[1:]
    if (cmd.name in ("iptables", "ip6tables") and any(x in ("-F", "--flush", "-X") for x in a)) \
            or (cmd.name == "ufw" and any(x in ("disable", "reset") for x in a)) \
            or (cmd.name == "nft" and "flush" in a):
        return [F("system.firewall", ASK, "security", "this removes firewall rules", cmd)]
    return []
