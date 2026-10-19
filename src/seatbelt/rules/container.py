"""Containers and package publishing."""
from __future__ import annotations

from ..context import Context, Resolver
from ..model import Finding
from ..shell import Command
from . import rule
from .common import ASK, F, level_for, prod_signal
from .opts import parse_words

HOST_MOUNTS = ("/:", "/etc:", "/root:", "/home:", "/var/run/docker.sock", "/run/docker.sock", "/proc:", "/sys:", "/boot:", "/dev:")


@rule("docker", "podman", "nerdctl", "docker-compose", "podman-compose")
def docker(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    args = cmd.argv[1:]
    o = parse_words(cmd.words[1:], {"-v", "--volume", "--mount", "-e", "--env", "-p", "--publish", "--name", "-w", "--workdir", "-u", "--user",
                                   "--network", "--net", "--cap-add", "--device", "--pid", "--userns", "-f", "--file", "-H", "--host", "--context"})
    tokens = [w.text for w in o.pos]
    if cmd.name.endswith("-compose"):
        tokens = ["compose"] + tokens
    verb = tokens[0] if tokens else ""
    sub = tokens[1] if len(tokens) > 1 else ""
    out: list[Finding] = []
    prod = prod_signal(cmd, ctx)
    where = " on a PRODUCTION host" if prod else ""

    if verb == "system" and sub == "prune":
        vols = o.has("--volumes")
        out.append(F("docker.prune", ASK, "irreversible" if vols else "destructive",
                     f"`docker system prune`{' --volumes' if vols else ''} removes stopped containers, unused images{' and volumes (data)' if vols else ''}{where}", cmd))
    elif verb == "volume" and sub in ("rm", "prune"):
        out.append(F("docker.volume", level_for(prod, True), "irreversible", f"`docker volume {sub}` deletes volume data{where}", cmd))
    elif verb in ("rm", "rmi", "container", "image") and (o.has("-v", "--volumes") or (any(w.dyn and "$(" in w.text for w in cmd.words) and verb in ("rm", "rmi"))):
        out.append(F("docker.remove-many", ASK, "destructive", f"removes containers/images selected at runtime or with their volumes{where}", cmd))
    elif verb == "compose" and sub in ("down", "rm") and (o.has("-v", "--volumes") or "--rmi" in args):
        out.append(F("docker.compose-down-volumes", level_for(prod, True), "irreversible", f"`compose {sub} -v` deletes the volumes (database data){where}", cmd))
    elif verb in ("push", "image", "manifest") and ("push" in tokens[:2]):
        out.append(F("publish.docker", ASK, "publish", "pushes an image to a registry, where others (and deployments) can pull it", cmd))
    elif verb in ("run", "create") or (verb == "container" and sub in ("run", "create")):
        vols = [v for k in ("-v", "--volume", "--mount") for v in o.values.get(k, [])]
        risky = []
        if o.has("--privileged"):
            risky.append("--privileged")
        if any(v.startswith(HOST_MOUNTS) or "source=/," in v or "source=/var/run/docker.sock" in v for v in vols):
            risky.append("a sensitive host path (or the Docker socket) mounted")
        if any(a in ("--pid=host", "--userns=host", "--net=host", "--network=host", "--ipc=host") for a in args) or \
                any(v in ("host",) for k in ("--pid", "--network", "--net", "--userns") for v in o.values.get(k, [])):
            risky.append("host namespaces")
        if any(c.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN") for c in o.values.get("--cap-add", [])):
            risky.append("dangerous capabilities")
        if risky:
            out.append(F("docker.escape", ASK, "privilege", f"this container gets control of the host: {', '.join(risky)}", cmd))
    return out


PUBLISH = {
    "npm": [("publish",), ("unpublish",), ("deprecate",), ("owner", "add"), ("access", "public"), ("dist-tag", "rm")],
    "yarn": [("publish",), ("npm", "publish")], "pnpm": [("publish",)], "bun": [("publish",)],
    "twine": [("upload",)], "poetry": [("publish",)], "flit": [("publish",)], "hatch": [("publish",)],
    "cargo": [("publish",), ("yank",), ("owner",)], "gem": [("push",), ("yank",)], "helm": [("push",)],
    "dotnet": [("nuget", "push")], "mvn": [("deploy",)], "gradle": [("publish",), ("publishToMavenRepository",)],
    "gh": [("release", "create")], "vsce": [("publish",)], "ovsx": [("publish",)],
}


@rule(*PUBLISH.keys())
def publish(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    tokens = [a for a in cmd.argv[1:] if not a.startswith("-")]
    if any(a in ("--dry-run", "-n") for a in cmd.argv[1:]):
        return []
    for pattern in PUBLISH.get(cmd.name, []):
        if tokens[: len(pattern)] == list(pattern):
            return [F("publish.package", ASK, "publish", f"`{cmd.name} {' '.join(pattern)}` publishes something others can install; it is hard to take back", cmd)]
    return []
