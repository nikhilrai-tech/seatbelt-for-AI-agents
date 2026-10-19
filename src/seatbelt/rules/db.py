"""Databases: SQL given to psql/mysql/sqlite3, Redis and Mongo one-liners, and the migration tools' destructive commands."""
from __future__ import annotations

import os
import re
from typing import Optional

from ..context import Context, Resolver
from ..model import Finding
from ..shell import Command
from . import rule
from .common import ASK, F, level_for, prod_signal
from .opts import parse_words

SQL_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "usql", "pgcli", "mycli", "litecli", "clickhouse-client", "snowsql", "cockroach", "duckdb"}
MAX_SQL_FILE = 512 * 1024

_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/|#[^\n]*", re.S)
_STRINGS = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"])*\"")


def scan_sql(text: str, prod: bool, cmd: Command, label: str = "") -> list[Finding]:
    """Look for statements that destroy or rewrite data. `prod` turns the irreversible ones into DENY."""
    out: list[Finding] = []
    where = " on a PRODUCTION database" if prod else ""
    pre = f"{label}: " if label else ""
    cleaned = _STRINGS.sub("''", _COMMENT.sub(" ", text))
    for raw in cleaned.split(";"):
        s = " ".join(raw.split())
        if not s:
            continue
        u = s.upper()
        if re.match(r"DROP\s+(DATABASE|SCHEMA)\b", u):
            out.append(F("sql.drop-database", level_for(prod, True), "irreversible", f"{pre}`DROP DATABASE/SCHEMA` deletes everything in it{where}", cmd))
        elif re.match(r"DROP\s+(TABLE|OWNED|TABLESPACE)\b", u):
            out.append(F("sql.drop-table", level_for(prod, True), "irreversible", f"{pre}`DROP TABLE` deletes the table and its data{where}", cmd))
        elif re.match(r"DROP\s+(VIEW|INDEX|USER|ROLE|EXTENSION|FUNCTION|TRIGGER|SEQUENCE|MATERIALIZED)\b", u):
            out.append(F("sql.drop", ASK, "destructive", f"{pre}`{u.split()[0]} {u.split()[1]}` removes a database object{where}", cmd))
        elif re.match(r"TRUNCATE\b", u):
            out.append(F("sql.truncate", level_for(prod, True), "irreversible", f"{pre}`TRUNCATE` empties the table instantly{where}", cmd))
        elif re.match(r"DELETE\s+FROM\b", u) and not re.search(r"\bWHERE\b", u):
            out.append(F("sql.delete-all", level_for(prod, True), "irreversible", f"{pre}`DELETE` with no WHERE removes every row{where}", cmd))
        elif re.match(r"UPDATE\b", u) and re.search(r"\bSET\b", u) and not re.search(r"\bWHERE\b", u):
            out.append(F("sql.update-all", level_for(prod, True), "destructive", f"{pre}`UPDATE` with no WHERE rewrites every row{where}", cmd))
        elif re.match(r"ALTER\s+TABLE\b", u) and re.search(r"\bDROP\s+(COLUMN|CONSTRAINT|PRIMARY|FOREIGN)\b", u):
            out.append(F("sql.alter-drop", ASK, "destructive", f"{pre}`ALTER TABLE ... DROP` removes a column or constraint{where}", cmd))
        elif re.match(r"(GRANT\s+ALL|ALTER\s+(USER|ROLE)\b.*\bSUPERUSER\b|CREATE\s+(USER|ROLE)\b.*\bSUPERUSER\b)", u):
            out.append(F("sql.privilege", ASK, "privilege", f"{pre}this grants broad database privileges", cmd))
        elif re.match(r"(COPY\b.*\b(TO|FROM)\s+PROGRAM|\\!|SELECT\s+LO_EXPORT|SELECT\s+PG_READ_FILE|LOAD_FILE\()", u) or "xp_cmdshell" in s.lower():
            out.append(F("sql.shell", ASK, "dynamic", f"{pre}this SQL can run commands or read files on the database host", cmd))
        elif prod and re.match(r"(INSERT|UPDATE|DELETE|MERGE|ALTER|CREATE|GRANT|REVOKE|REPLACE|UPSERT)\b", u):
            out.append(F("sql.prod-write", ASK, "production", f"{pre}this writes data{where}", cmd))
    return out


def _read_sql_file(path: str) -> Optional[str]:
    try:
        if os.path.isfile(path) and os.stat(path).st_size <= MAX_SQL_FILE:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
    except OSError:
        pass
    return None


def sql_sources(cmd: Command, res: Resolver) -> list[tuple[str, str]]:
    """(label, SQL text) for everything this client is told to execute."""
    out: list[tuple[str, str]] = []
    o = parse_words(cmd.words[1:], {"-c", "--command", "-e", "--execute", "-f", "--file", "-h", "--host", "-U", "-u", "-d", "-p", "-P",
                                    "--eval", "-S", "--query", "-q", "-x", "-b", "-i", "-o", "--user", "--password", "-D", "--database"})
    for key in ("-c", "--command", "-e", "--execute", "--query"):
        out += [("inline SQL", v) for v in o.values.get(key, [])]
    for key in ("-f", "--file"):
        for v in o.values.get(key, []):
            r = res.resolve(v, cmd.cwd)
            text = _read_sql_file(r.path) if r.path else None
            if text:
                out.append((f"in {os.path.basename(v)}", text))
    for r in cmd.redirects:
        if r.op in ("<<", "<<-") and r.body:
            out.append(("SQL here-doc", r.body))
        elif r.op == "<<<" and r.target:
            out.append(("SQL here-string", r.target))
        elif r.op == "<" and r.target:
            p = res.resolve(r.target, cmd.cwd).path
            text = _read_sql_file(p) if p else None
            if text:
                out.append((f"in {os.path.basename(r.target)}", text))
    if cmd.name == "sqlite3":  # sqlite3 DB "SQL"
        pos = [w.text for w in o.pos]
        if len(pos) >= 2:
            out.append(("inline SQL", pos[1]))
    return out


@rule(*SQL_CLIENTS)
def sql_client(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    prod = prod_signal(cmd, ctx)
    out: list[Finding] = []
    for label, text in sql_sources(cmd, res):
        out += scan_sql(text, prod, cmd, label)
    return out


@rule("redis-cli", "valkey-cli", "keydb-cli")
def redis(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    prod = prod_signal(cmd, ctx)
    words = {a.upper() for a in cmd.argv[1:] if not a.startswith("-")}
    where = " on a PRODUCTION server" if prod else ""
    if words & {"FLUSHALL", "FLUSHDB"}:
        return [F("redis.flush", level_for(prod, True), "irreversible", f"`FLUSHALL/FLUSHDB` deletes every key{where}", cmd)]
    if words & {"SHUTDOWN", "DEBUG", "SLAVEOF", "REPLICAOF", "MIGRATE"} or ("CONFIG" in words and "SET" in words):
        return [F("redis.admin", ASK, "destructive", f"this Redis admin command can take the server down or change replication{where}", cmd)]
    return []


@rule("mongosh", "mongo")
def mongo(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    prod = prod_signal(cmd, ctx)
    code = " ".join(v for a, v in zip(cmd.argv, cmd.argv[1:]) if a in ("--eval", "--file")) or " ".join(cmd.argv[1:])
    if re.search(r"dropDatabase\(|\.drop\(\)|dropIndexes\(|deleteMany\(\s*\{\s*\}\s*\)|remove\(\s*\{\s*\}\s*\)|\.dropCollection\(", code):
        return [F("mongo.drop", level_for(prod, True), "irreversible", f"this drops or empties MongoDB data{' on PRODUCTION' if prod else ''}", cmd)]
    return []


MIGRATION_DESTRUCTIVE = {
    "dropdb": None, "dropuser": None, "dropdb.exe": None,
    "prisma": [("migrate", "reset"), ("db", "push", "--force-reset"), ("db", "execute")],
    "rails": [("db:drop",), ("db:reset",), ("db:schema:load",), ("db:setup",), ("db:migrate:reset",), ("db:purge",)],
    "rake": [("db:drop",), ("db:reset",), ("db:schema:load",), ("db:setup",), ("db:purge",)],
    "sequelize": [("db:drop",), ("db:migrate:undo:all",)], "sequelize-cli": [("db:drop",), ("db:migrate:undo:all",)],
    "knex": [("migrate:rollback", "--all"), ("migrate:down",)], "typeorm": [("schema:drop",)],
    "alembic": [("downgrade", "base")], "flask": [("db", "downgrade", "base")],
    "liquibase": [("dropAll",)], "flyway": [("clean",)], "dbmate": [("drop",)], "diesel": [("database", "reset"), ("database", "drop")],
    "sqlx": [("database", "drop"), ("database", "reset")], "mix": [("ecto.drop",), ("ecto.reset",)],
    "artisan": [("migrate:fresh",), ("db:wipe",), ("migrate:reset",)], "mysqladmin": [("drop",), ("shutdown",)],
    "pg_restore": [("--clean",), ("-c",)], "pg_resetwal": None, "dropdb ": None,
}


@rule(*MIGRATION_DESTRUCTIVE.keys(), "python", "python3", "django-admin", "manage.py", "php")
def migrations(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    name = cmd.name
    argv = cmd.argv[1:]
    prod = prod_signal(cmd, ctx)
    where = " on a PRODUCTION database" if prod else ""
    hit = False
    if name in ("python", "python3", "django-admin", "manage.py", "php"):
        words = set(argv)
        if name == "php":
            hit = bool(words & {"migrate:fresh", "db:wipe", "migrate:reset"}) and any(a.endswith("artisan") or a == "artisan" for a in argv)
        else:
            managed = name == "django-admin" or any(a.endswith("manage.py") for a in argv)
            hit = managed and bool(words & {"flush", "sqlflush", "reset_db", "reset_schema", "dbrestore"}) or \
                (managed and "migrate" in words and "zero" in words)
    elif MIGRATION_DESTRUCTIVE.get(name) is None:
        hit = name in ("dropdb", "dropuser", "dropdb.exe", "pg_resetwal")
    else:
        hit = any(all(p in argv for p in pattern) for pattern in MIGRATION_DESTRUCTIVE[name])
    if hit:
        return [F("db.destructive", level_for(prod, True), "irreversible", f"`{name}` here drops or resets a database{where}", cmd)]
    return []
