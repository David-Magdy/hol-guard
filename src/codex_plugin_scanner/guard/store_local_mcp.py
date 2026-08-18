"""This-device MCP custom-extension grant lookup."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING

from .runtime.local_cli_commands import LocalCliCommand, LocalCliCommandState
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id
from .store_local_cli import _grant_from_row, _row_values
from .store_local_cli_schema import ensure_local_cli_schema


class StoreLocalMcpMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

        def read_local_cli_command_catalog(self, cli_id: str) -> list[LocalCliCommand]: ...

        def read_local_cli_command_states(self, cli_id: str) -> dict[str, LocalCliCommandState]: ...

    def find_local_mcp_observation(
        self,
        *,
        server_identity_hash: str | None = None,
        command: str | None = None,
        args_hash: str | None = None,
    ) -> dict[str, object] | None:
        hash_value = _normalized_identity_hash(server_identity_hash)
        if hash_value is None and (not command or not args_hash):
            return None
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            row = connection.execute(
                """
                select cli_id, identity_hash, kind, name, interpreter_name, example_label,
                       server_identity_hash, server_command, server_args_hash
                from local_cli_observation
                where surface = 'mcp'
                  and (
                    (? is not null and (server_identity_hash = ? or identity_hash = ?))
                    or (
                      ? is not null and ? is not null
                      and server_command = ? and server_args_hash = ?
                    )
                  )
                order by last_seen_at desc, cli_id asc
                limit 1
                """,
                (
                    hash_value,
                    hash_value,
                    hash_value,
                    command,
                    args_hash,
                    command,
                    args_hash,
                ),
            ).fetchone()
        if row is None:
            return None
        values = _row_values(row, 9)
        cli_id = values[0]
        identity_hash = values[1]
        if not isinstance(cli_id, str) or not isinstance(identity_hash, str):
            return None
        return {
            "cli_id": cli_id,
            "identity_hash": identity_hash,
            "kind": values[2],
            "name": values[3],
            "interpreter_name": values[4],
            "example_label": values[5],
            "server_identity_hash": values[6],
            "server_command": values[7],
            "server_args_hash": values[8],
        }

    def ensure_local_mcp_observation(
        self,
        identity: UnlistedCliIdentity,
        *,
        seen_at: str,
        server_identity_hash: str,
        server_command: str,
        server_args_hash: str,
    ) -> str:
        """Insert or refresh an MCP observation without incrementing observed_count."""

        if not is_local_cli_id(identity.cli_id):
            raise ValueError("invalid local CLI id")
        existing = self.find_local_mcp_observation(
            server_identity_hash=server_identity_hash,
            command=server_command,
            args_hash=server_args_hash,
        )
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            if existing is None:
                try:
                    _ = connection.execute(
                        """
                        insert into local_cli_observation (
                            cli_id, identity_hash, kind, name, interpreter_name, example_label,
                            observed_count, last_seen_at, source_path, help_status, surface,
                            server_identity_hash, server_command, server_args_hash
                        ) values (?, ?, ?, ?, ?, ?, 1, ?, null, null, 'mcp', ?, ?, ?)
                        """,
                        (
                            identity.cli_id,
                            identity.identity_hash,
                            identity.kind,
                            identity.name,
                            identity.interpreter_name,
                            identity.example_label,
                            seen_at,
                            server_identity_hash,
                            server_command,
                            server_args_hash,
                        ),
                    )
                    return identity.cli_id
                except sqlite3.IntegrityError:
                    return identity.cli_id
            cli_id = str(existing["cli_id"])
            _ = connection.execute(
                """
                update local_cli_observation
                set name = ?, example_label = ?, last_seen_at = ?,
                    server_identity_hash = coalesce(server_identity_hash, ?),
                    server_command = coalesce(server_command, ?),
                    server_args_hash = coalesce(server_args_hash, ?)
                where cli_id = ?
                """,
                (
                    identity.name,
                    identity.example_label,
                    seen_at,
                    server_identity_hash,
                    server_command,
                    server_args_hash,
                    cli_id,
                ),
            )
            return cli_id

    def read_local_mcp_grant(
        self,
        server_identity_hash: str,
        *,
        command: str | None = None,
        args_hash: str | None = None,
    ) -> dict[str, object] | None:
        if not isinstance(server_identity_hash, str) or len(server_identity_hash) != 64:
            return None
        server_identity_hash = server_identity_hash.lower()
        if any(character not in "0123456789abcdef" for character in server_identity_hash):
            return None
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            observation = connection.execute(
                """
                select cli_id, identity_hash
                from local_cli_observation
                where surface = 'mcp'
                  and (
                    server_identity_hash = ?
                    or identity_hash = ?
                    or (
                      ? is not null and ? is not null
                      and server_command = ? and server_args_hash = ?
                    )
                  )
                order by last_seen_at desc, cli_id asc
                limit 1
                """,
                (
                    server_identity_hash,
                    server_identity_hash,
                    command,
                    args_hash,
                    command,
                    args_hash,
                ),
            ).fetchone()
            if observation is None:
                return None
            cli_id, identity_hash = _row_values(observation, 2)
            if not isinstance(cli_id, str) or not isinstance(identity_hash, str):
                return None
            grant_row = connection.execute(
                "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant where cli_id = ?",
                (cli_id,),
            ).fetchone()
        if grant_row is None:
            return None
        grant = _grant_from_row(grant_row)
        if grant["identity_hash"] != identity_hash:
            return None
        if grant["state"] == "blocked":
            grant["commands"] = []
            grant["command_states"] = {}
            return grant
        grant["commands"] = self.read_local_cli_command_catalog(cli_id)
        grant["command_states"] = self.read_local_cli_command_states(cli_id)
        return grant


def _normalized_identity_hash(value: str | None) -> str | None:
    if not isinstance(value, str) or len(value) != 64:
        return None
    lowered = value.lower()
    if any(character not in "0123456789abcdef" for character in lowered):
        return None
    return lowered
