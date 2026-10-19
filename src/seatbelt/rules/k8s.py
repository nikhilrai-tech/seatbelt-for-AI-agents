"""kubectl / oc / helm. The cluster context is read from the command, the environment or kubeconfig's current-context."""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..context import Context, Resolver
from ..model import Finding
from ..shell import Command
from . import rule
from .common import ASK, F, is_dry_run, level_for
from .opts import parse_words

KUBECTL_VALUE_OPTS = {"-n", "--namespace", "--context", "--kubeconfig", "-o", "--output", "-l", "--selector", "-f", "--filename",
                      "-c", "--container", "--cluster", "--user", "-s", "--server", "--field-selector", "-L", "--sort-by",
                      "--replicas", "--type", "-p", "--patch", "--grace-period", "--timeout", "--as", "--as-group", "-k", "--kustomize"}
CLUSTER_SCOPED = {"ns", "namespace", "namespaces", "node", "nodes", "no", "crd", "crds", "customresourcedefinition", "customresourcedefinitions",
                  "pv", "persistentvolume", "persistentvolumes", "pvc", "persistentvolumeclaim", "persistentvolumeclaims",
                  "clusterrole", "clusterroles", "clusterrolebinding", "clusterrolebindings", "storageclass", "storageclasses", "all"}
SECRET_KINDS = {"secret", "secrets"}
HELM_VALUE_OPTS = {"-n", "--namespace", "--kube-context", "-f", "--values", "--set", "--set-string", "--version", "--repo", "-o", "--output",
                   "--timeout", "--kubeconfig"}


def current_context(cmd: Command, ctx: Context, explicit: str = "") -> str:
    """The kube context this command will act on: --context, else $KUBECONFIG/~/.kube/config `current-context`."""
    if explicit:
        return explicit
    path = (ctx.environ.get("KUBECONFIG") or "").split(os.pathsep)[0] or os.path.join(ctx.home, ".kube", "config")
    try:
        p = Path(path)
        if p.is_file() and p.stat().st_size < 2 * 1024 * 1024:
            m = re.search(r"^current-context:\s*['\"]?([^'\"\s]+)", p.read_text(errors="replace"), re.M)
            if m:
                return m.group(1)
    except OSError:
        pass
    return ""


@rule("kubectl", "oc")
def kubectl(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if is_dry_run(cmd):
        return []
    o = parse_words(cmd.words[1:], KUBECTL_VALUE_OPTS)
    tokens = [w.text for w in o.pos]
    verb, rest = (tokens[0], tokens[1:]) if tokens else ("", [])
    kube_ctx = current_context(cmd, ctx, (o.values.get("--context") or [""])[0])
    ns = (o.values.get("-n") or o.values.get("--namespace") or [""])[0]
    prod = ctx.is_prod(kube_ctx, ns, " ".join(cmd.argv[1:]), *cmd.env.values())
    where = f" on the PRODUCTION cluster ({kube_ctx or ns})" if prod else ""
    out: list[Finding] = []

    if verb == "delete":
        kinds = {k.lower().split("/")[0] for k in (rest[0].split(",") if rest else [])}
        everything = o.has("--all", "-A", "--all-namespaces") or "all" in kinds
        irreversible = everything or bool(kinds & CLUSTER_SCOPED)
        what = "everything of that kind" if everything else (f"a {sorted(kinds & CLUSTER_SCOPED)[0]}" if kinds & CLUSTER_SCOPED else "resources")
        out.append(F("k8s.delete", level_for(prod, irreversible), "irreversible" if irreversible else "destructive",
                     f"`kubectl delete` removes {what}{where}", cmd))
    elif verb in ("drain", "cordon", "taint"):
        out.append(F("k8s.node", ASK, "destructive", f"`kubectl {verb}` disrupts the workloads on a node{where}", cmd))
    elif verb == "scale" and any(v in ("0",) for v in o.values.get("--replicas", [])) or (verb == "scale" and "--replicas=0" in cmd.argv):
        out.append(F("k8s.scale-zero", ASK, "destructive", f"scaling to zero replicas takes the service down{where}", cmd))
    elif verb in ("apply", "create", "replace", "patch", "edit", "set", "annotate", "label", "rollout", "expose", "autoscale", "run", "cp"):
        if o.has("--prune") or (verb == "replace" and o.has("--force")):
            out.append(F("k8s.prune", ASK, "destructive", f"`kubectl {verb}` with --prune/--force deletes live resources not in the manifest{where}", cmd))
        elif verb == "rollout" and rest[:1] in (["undo"], ["restart"]) or prod:
            if prod:
                out.append(F("k8s.prod-change", ASK, "production", f"`kubectl {verb}` changes resources{where}", cmd))
    elif verb in ("get", "describe") and rest and rest[0].lower().split(",")[0] in SECRET_KINDS:
        out.append(F("k8s.secret-read", ASK, "secret", f"`kubectl {verb} secret` prints cluster secrets{where}", cmd))
    elif verb == "config":
        sub = rest[0] if rest else ""
        if sub == "view" and o.has("--raw"):
            out.append(F("k8s.config-raw", ASK, "secret", "`kubectl config view --raw` prints cluster credentials", cmd))
        elif sub == "set-credentials":
            out.append(F("k8s.config-creds", ASK, "privilege", "`kubectl config set-credentials` stores new cluster credentials", cmd))
        elif sub == "use-context" and len(rest) > 1 and ctx.is_prod(rest[1]):
            out.append(F("k8s.use-prod", ASK, "production", f"switches kubectl to the production context ({rest[1]})", cmd))
    return out


@rule("helm", "helmfile")
def helm(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if is_dry_run(cmd):
        return []
    o = parse_words(cmd.words[1:], HELM_VALUE_OPTS)
    tokens = [w.text for w in o.pos]
    verb = tokens[0] if tokens else ""
    kube_ctx = current_context(cmd, ctx, (o.values.get("--kube-context") or [""])[0])
    ns = (o.values.get("-n") or o.values.get("--namespace") or [""])[0]
    prod = ctx.is_prod(kube_ctx, ns, " ".join(cmd.argv[1:]), *cmd.env.values())
    where = " on the PRODUCTION cluster" if prod else ""
    if verb in ("uninstall", "delete") or (cmd.name == "helmfile" and verb in ("destroy", "delete")):
        return [F("helm.uninstall", level_for(prod, True), "irreversible", f"`helm {verb}` removes a release and its resources{where}", cmd)]
    if verb in ("upgrade", "install", "rollback", "apply", "sync") and prod:
        return [F("helm.prod-change", ASK, "production", f"`helm {verb}` changes a release{where}", cmd)]
    return []
