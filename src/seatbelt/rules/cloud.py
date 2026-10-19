"""Cloud CLIs: aws, gcloud/gsutil, az, and the common PaaS tools. Production is detected, not assumed."""
from __future__ import annotations

from ..context import Context, Resolver
from ..model import Finding
from ..shell import Command
from . import rule
from .common import ASK, DENY, F, classify_tokens, has_path, is_dry_run, level_for, loose_values, prod_signal

AWS_VALUE_OPTS = {"--profile", "--region", "--output", "--endpoint-url", "--query", "--cli-read-timeout", "--cli-connect-timeout",
                  "--ca-bundle", "--color", "--cli-input-json", "--cli-input-yaml", "--cli-binary-format", "--cli-auto-prompt"}

# (service, operation) pairs whose effect cannot be undone
AWS_IRREVERSIBLE = {
    ("rds", "delete-db-instance"), ("rds", "delete-db-cluster"), ("rds", "delete-db-snapshot"), ("rds", "delete-db-cluster-snapshot"),
    ("s3", "rb"), ("s3api", "delete-bucket"), ("dynamodb", "delete-table"), ("dynamodb", "delete-backup"),
    ("kms", "schedule-key-deletion"), ("kms", "disable-key"), ("ec2", "terminate-instances"), ("ec2", "delete-volume"),
    ("ec2", "delete-snapshot"), ("ec2", "delete-vpc"), ("cloudformation", "delete-stack"), ("eks", "delete-cluster"),
    ("eks", "delete-nodegroup"), ("efs", "delete-file-system"), ("elasticache", "delete-cache-cluster"),
    ("elasticache", "delete-replication-group"), ("redshift", "delete-cluster"), ("route53", "delete-hosted-zone"),
    ("secretsmanager", "delete-secret"), ("logs", "delete-log-group"), ("lambda", "delete-function"),
    ("organizations", "close-account"), ("organizations", "remove-account-from-organization"), ("iam", "delete-user"),
    ("iam", "delete-role"), ("backup", "delete-backup-vault"), ("backup", "delete-recovery-point"), ("glacier", "delete-vault"),
    ("ecr", "delete-repository"), ("opensearch", "delete-domain"), ("es", "delete-elasticsearch-domain"),
    ("cloudfront", "delete-distribution"), ("kinesis", "delete-stream"), ("docdb", "delete-db-cluster"), ("neptune", "delete-db-cluster"),
}
AWS_ACCESS_CHANGES = {"create-access-key", "create-user", "create-login-profile", "attach-user-policy", "attach-role-policy",
                      "attach-group-policy", "put-user-policy", "put-role-policy", "put-group-policy", "update-assume-role-policy",
                      "add-user-to-group", "create-role", "create-policy-version", "update-login-profile", "create-service-linked-role",
                      "set-default-policy-version", "update-access-key"}
AWS_SECRET_READS = {("secretsmanager", "get-secret-value"), ("kms", "decrypt"), ("iam", "get-login-profile"), ("sts", "get-session-token"),
                    ("sts", "assume-role"), ("ecr", "get-login-password"), ("ecr", "get-authorization-token"),
                    ("codeartifact", "get-authorization-token"), ("rds", "generate-db-auth-token"), ("eks", "get-token")}
EXPENSIVE_PREFIXES = ("p3", "p4", "p5", "g5", "g6", "x1", "x2", "u-", "dl1", "trn1", "inf2", "hpc", "m5.metal", "c5.metal", "i3.metal",
                      "m6i.32", "m6i.48", "r5.24", "r6i.32", "c6i.32", "m7i.48")


def _aws_parts(cmd: Command) -> tuple[str, str, list]:
    words = cmd.words[1:]
    i = 0
    while i < len(words) and words[i].text.startswith("-"):
        i += 2 if words[i].text in AWS_VALUE_OPTS else 1
    service = words[i].text if i < len(words) else ""
    op = words[i + 1].text if i + 1 < len(words) else ""
    return service, op, words[i + 2:]


@rule("aws")
def aws(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    service, op, rest = _aws_parts(cmd)
    if not service or not op or is_dry_run(cmd):
        return []
    values = loose_values(cmd.argv[1:])
    profile = (values.get("--profile") or [""])[0]
    prod = prod_signal(cmd, ctx, profile)
    where = " in PRODUCTION" if prod else ""
    out: list[Finding] = []
    rest_flags = {w.text for w in rest}
    key = (service, op)

    if service == "s3":
        recursive = "--recursive" in rest_flags
        if op == "rb":
            lvl = level_for(prod, True)
            out.append(F("aws.s3.rb", lvl, "irreversible", f"`aws s3 rb` deletes a bucket{' and everything in it' if '--force' in rest_flags else ''}{where}", cmd))
        elif op in ("rm", "mv") and (recursive or op == "rm"):
            irreversible = recursive and op == "rm"
            out.append(F("aws.s3.rm", level_for(prod, irreversible), "irreversible" if irreversible else "destructive",
                         f"`aws s3 {op}{' --recursive' if recursive else ''}` removes objects{where}", cmd))
        elif op == "sync" and "--delete" in rest_flags:
            out.append(F("aws.s3.sync-delete", level_for(prod, False), "destructive", f"`aws s3 sync --delete` removes destination objects that are not in the source{where}", cmd))
        elif op in ("cp", "mv", "sync", "mb", "website") and prod:
            out.append(F("aws.prod-change", ASK, "production", f"`aws s3 {op}` changes data{where}", cmd))
        return out

    kind = ("destructive" if op.startswith(("delete-", "terminate-", "remove-", "purge-", "destroy-", "deregister-", "schedule-", "close-", "disable-key"))
            else "read" if op.startswith(("describe-", "get-", "list-", "head-", "lookup-", "search-", "batch-get-", "select-", "validate-", "check-",
                                           "estimate-", "simulate-", "filter-", "tail", "scan", "query", "help", "wait", "ls"))
            else "mutating")
    if key in AWS_SECRET_READS or (service == "ssm" and op in ("get-parameter", "get-parameters", "get-parameters-by-path") and "--with-decryption" in rest_flags):
        out.append(F("aws.secret-read", ASK, "secret", f"`aws {service} {op}` prints a secret value", cmd))
    if kind == "destructive":
        irreversible = key in AWS_IRREVERSIBLE or "--skip-final-snapshot" in rest_flags or "--force-delete-without-recovery" in rest_flags
        out.append(F("aws.destructive", level_for(prod, irreversible), "irreversible" if irreversible else "destructive",
                     f"`aws {service} {op}` deletes or tears down a resource{where}", cmd))
    elif op in AWS_ACCESS_CHANGES:
        out.append(F("aws.access-change", ASK, "privilege", f"`aws {service} {op}` changes who can access the account", cmd))
    elif kind == "mutating":
        if service == "ec2" and op == "run-instances":
            count = next((v for v in values.get("--count", []) + values.get("--max-count", []) if v.isdigit()), "1")
            types = values.get("--instance-type", [])
            if int(count) > 5 or any(t.startswith(EXPENSIVE_PREFIXES) for t in types):
                out.append(F("aws.cost", ASK, "cost", f"launches {count} instance(s){' of ' + types[0] if types else ''}, which can be expensive", cmd))
        if (service == "ec2" and op.startswith("authorize-security-group") and any("0.0.0.0/0" in w.text or "::/0" in w.text for w in rest)) or \
                (service == "s3api" and op in ("put-public-access-block", "put-bucket-acl", "put-bucket-policy")):
            out.append(F("aws.exposure", ASK, "exposure", f"`aws {service} {op}` can open resources to the whole internet", cmd))
        if prod:
            out.append(F("aws.prod-change", ASK, "production", f"`aws {service} {op}` changes a resource{where}", cmd))
    return out


GCLOUD_IRREVERSIBLE = [("projects", "delete"), ("sql", "instances", "delete"), ("container", "clusters", "delete"),
                       ("storage", "buckets", "delete"), ("compute", "disks", "delete"), ("spanner", "instances", "delete"),
                       ("spanner", "databases", "delete"), ("bigtable", "instances", "delete"), ("firestore", "databases", "delete"),
                       ("kms", "keys", "versions", "destroy"), ("secrets", "delete"), ("alloydb", "clusters", "delete"),
                       ("filestore", "instances", "delete"), ("dns", "managed-zones", "delete"), ("organizations", "delete")]
AZ_IRREVERSIBLE = [("group", "delete"), ("sql", "server", "delete"), ("sql", "db", "delete"), ("storage", "account", "delete"),
                   ("aks", "delete"), ("keyvault", "purge"), ("keyvault", "delete"), ("cosmosdb", "delete"), ("webapp", "delete"),
                   ("acr", "delete"), ("storage", "container", "delete"), ("postgres", "server", "delete"), ("mysql", "server", "delete"),
                   ("postgres", "flexible-server", "delete"), ("mysql", "flexible-server", "delete"), ("vm", "delete"), ("disk", "delete"),
                   ("account", "management-group", "delete"), ("ad", "app", "delete"), ("role", "assignment", "delete")]


def _tokens(cmd: Command) -> list[str]:
    return [w.text for w in cmd.words[1:] if not w.text.startswith("-")]


def _generic_cli(cmd: Command, ctx: Context, name: str, irreversible_paths: list[tuple[str, ...]]) -> list[Finding]:
    if is_dry_run(cmd):
        return []
    tokens = _tokens(cmd)[:7]
    kind, idx = classify_tokens(tokens)
    prod = prod_signal(cmd, ctx)
    where = " in PRODUCTION" if prod else ""
    shown = " ".join(tokens[: idx + 1]) if idx >= 0 else name
    if kind == "destructive":
        irreversible = any(has_path(tokens, *p) for p in irreversible_paths)
        return [F(f"{name}.destructive", level_for(prod, irreversible), "irreversible" if irreversible else "destructive",
                  f"`{name} {shown}` deletes or tears down a resource{where}", cmd)]
    if kind == "mutating" and prod:
        return [F(f"{name}.prod-change", ASK, "production", f"`{name} {shown}` changes a resource{where}", cmd)]
    return []


@rule("gcloud")
def gcloud(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    return _generic_cli(cmd, ctx, "gcloud", GCLOUD_IRREVERSIBLE)


@rule("az")
def az(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    return _generic_cli(cmd, ctx, "az", AZ_IRREVERSIBLE)


@rule("gsutil", "gcloud-storage")
def gsutil(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    tokens = [w.text for w in cmd.words[1:] if not w.text.startswith("-")]
    flags = {w.text for w in cmd.words[1:]}
    prod = prod_signal(cmd, ctx)
    if tokens and tokens[0] in ("rm", "rb") or ("rm" in tokens[:2]):
        irreversible = tokens[0] == "rb" or any(f in flags for f in ("-r", "-R", "--recursive")) or any(a.startswith("-") and "r" in a[1:] and not a.startswith("--") for a in flags)
        return [F("gsutil.rm", level_for(prod, irreversible), "irreversible" if irreversible else "destructive",
                  f"`gsutil {tokens[0]}` deletes objects{' recursively' if irreversible else ''}{' in PRODUCTION' if prod else ''}", cmd)]
    return []


@rule("doctl", "heroku", "flyctl", "fly", "vercel", "netlify", "firebase", "supabase", "wrangler", "railway", "pscale", "render", "scalingo")
def paas(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    name = cmd.name
    args = [w.text for w in cmd.words[1:]]
    prod = prod_signal(cmd, ctx)
    where = " in PRODUCTION" if prod else ""
    destructive_words = {"destroy", "delete", "rm", "remove", "reset", "drop", "purge", "wipe"}
    colon = [a for a in args if ":" in a and a.split(":")[-1] in destructive_words]  # heroku apps:destroy, netlify sites:delete
    tokens = [a for a in args if not a.startswith("-")][:4]
    hit = colon or [t for t in tokens if t.lower() in destructive_words]
    if name == "heroku":
        hit = hit or [a for a in args if a in ("pg:reset", "pg:killall", "pg:copy")]
    if name in ("vercel",) and tokens and tokens[0] in ("remove", "rm"):
        hit = hit or [tokens[0]]
    if hit:
        return [F("paas.destructive", level_for(prod, True), "irreversible",
                  f"`{name} {hit[0]}` deletes or resets a hosted resource{where}", cmd)]
    if name == "firebase" and any(a in ("--all-collections", "--shallow") for a in args):
        return [F("paas.destructive", level_for(prod, True), "irreversible", f"`firebase` deleting all collections{where}", cmd)]
    if prod and tokens and any(t in ("deploy", "up", "release", "promote", "scale", "push") for t in tokens):
        return [F("paas.prod-change", ASK, "production", f"`{name} {tokens[0]}` changes a live service{where}", cmd)]
    return []


@rule("gh")
def github(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    args = [w.text for w in cmd.words[1:]]
    tokens = [a for a in args if not a.startswith("-")]
    out: list[Finding] = []
    if has_path(tokens, "repo", "delete"):
        out.append(F("gh.repo-delete", DENY, "irreversible", "`gh repo delete` permanently deletes a repository", cmd))
    elif has_path(tokens, "repo", "archive") or has_path(tokens, "release", "delete") or has_path(tokens, "secret", "delete") \
            or has_path(tokens, "variable", "delete") or has_path(tokens, "workflow", "disable") or has_path(tokens, "gist", "delete"):
        out.append(F("gh.destructive", ASK, "destructive", f"`gh {' '.join(tokens[:2])}` removes or disables something on GitHub", cmd))
    if tokens[:1] == ["api"]:
        method = next((args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-X", "--method")), "GET").upper()
        if method in ("DELETE", "PUT", "PATCH", "POST") and any(a.startswith(("/repos/", "repos/", "/orgs/", "/user")) for a in args):
            out.append(F("gh.api-write", ASK if method != "DELETE" else DENY, "destructive" if method == "DELETE" else "production",
                         f"`gh api -X {method}` changes GitHub data", cmd))
    if has_path(tokens, "pr", "merge") and any(a in ("--admin",) for a in args):
        out.append(F("gh.pr-merge-admin", ASK, "privilege", "`gh pr merge --admin` bypasses branch protection", cmd))
    return out
