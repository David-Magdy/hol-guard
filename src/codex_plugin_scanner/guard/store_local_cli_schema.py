"""Forward-only SQLite schema for unlisted CLI observations and grants."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Final, cast

LOCAL_CLI_SCHEMA_VERSION: Final = 1
_SCHEMA_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v1").hexdigest()


def ensure_local_cli_schema(connection: sqlite3.Connection) -> None:
    _ = connection.execute(
        """
        create table if not exists local_cli_schema_migration (
            singleton integer primary key check (singleton = 1),
            version integer not null,
            checksum text not null
        )
        """
    )
    row = cast(
        object,
        connection.execute("select version, checksum from local_cli_schema_migration where singleton = 1").fetchone(),
    )
    if row is None:
        _ = connection.execute(
            "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?, ?)",
            (LOCAL_CLI_SCHEMA_VERSION, _SCHEMA_CHECKSUM),
        )
    else:
        version, checksum = _marker(row)
        if version != LOCAL_CLI_SCHEMA_VERSION or checksum != _SCHEMA_CHECKSUM:
            raise ValueError("unsupported or invalid local CLI schema")
    _ = connection.execute(
        """
        create table if not exists local_cli_observation (
            cli_id text primary key,
            identity_hash text not null,
            kind text not null check (kind in ('executable', 'script')),
            name text not null,
            interpreter_name text,
            example_label text not null,
            observed_count integer not null check (observed_count >= 1),
            last_seen_at text not null
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists local_cli_grant (
            cli_id text primary key,
            identity_hash text not null,
            state text not null check (state in ('allowed', 'blocked')),
            revision integer not null check (revision >= 1),
            updated_at text not null
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists local_cli_authority (
            singleton integer primary key check (singleton = 1),
            revision integer not null check (revision >= 0)
        )
        """
    )
    _ = connection.execute(
        "insert or ignore into local_cli_authority (singleton, revision) values (1, 0)"
    )


def _marker(row: object) -> tuple[int, str]:
    if isinstance(row, sqlite3.Row):
        version_raw = cast(object, row["version"])
        checksum_raw = cast(object, row["checksum"])
    elif isinstance(row, tuple):
        values = cast(tuple[object, ...], row)
        if len(values) != 2:
            raise ValueError("invalid local CLI schema marker")
        version_raw, checksum_raw = values
    else:
        raise ValueError("invalid local CLI schema marker")
    if type(version_raw) is not int or not isinstance(checksum_raw, str):
        raise ValueError("invalid local CLI schema marker")
    return version_raw, checksum_raw
