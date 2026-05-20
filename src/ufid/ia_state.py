from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from ufid.ia_client import IAFile


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Checkpoint:
    crawl_key: str
    query: str
    cursor: str | None
    completed: bool
    imported_item_count: int | None
    updated_at: str


@dataclass(frozen=True)
class ItemState:
    identifier: str
    status: str
    attempts: int
    error: str | None


@dataclass(frozen=True)
class FileState:
    item_identifier: str
    name: str
    status: str
    attempts: int
    ufid_file_id: int | None
    error: str | None


@dataclass(frozen=True)
class QueuedFile:
    item_identifier: str
    name: str
    source: str | None
    format: str | None
    size_bytes: int | None
    md5: str | None
    sha1: str | None
    crc32: str | None
    url: str | None
    status: str
    attempts: int
    ufid_file_id: int | None
    error: str | None
    needs_downloaded_identity: bool
    identity_metadata_status: str
    identity_metadata_missing: tuple[str, ...]


class IAIngestState:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent and str(self.path.parent) != ".":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode = MEMORY")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.initialize()

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS ia_ingest_checkpoint (
                crawl_key TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                cursor TEXT,
                completed INTEGER NOT NULL DEFAULT 0,
                imported_item_count INTEGER,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ia_ingest_item (
                identifier TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                title TEXT,
                mediatype TEXT,
                status TEXT NOT NULL,
                metadata_json TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                first_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ia_ingest_file (
                item_identifier TEXT NOT NULL REFERENCES ia_ingest_item(identifier)
                    ON DELETE CASCADE,
                name TEXT NOT NULL,
                source TEXT,
                format TEXT,
                size_bytes INTEGER,
                md5 TEXT,
                sha1 TEXT,
                crc32 TEXT,
                url TEXT,
                status TEXT NOT NULL,
                ufid_file_id INTEGER,
                downloaded_path TEXT,
                needs_downloaded_identity INTEGER NOT NULL DEFAULT 0,
                identity_metadata_status TEXT NOT NULL DEFAULT 'unknown',
                identity_metadata_missing TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                first_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (item_identifier, name)
            );

            CREATE TABLE IF NOT EXISTS ia_ingest_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                item_identifier TEXT,
                file_name TEXT,
                message TEXT NOT NULL,
                details_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ia_ingest_item_status
            ON ia_ingest_item (status);

            CREATE INDEX IF NOT EXISTS idx_ia_ingest_file_status
            ON ia_ingest_file (status);

            CREATE INDEX IF NOT EXISTS idx_ia_ingest_event_created
            ON ia_ingest_event (created_at);
            """
        )
        self._ensure_file_column(
            "needs_downloaded_identity",
            "INTEGER NOT NULL DEFAULT 0",
        )
        self._ensure_file_column(
            "identity_metadata_status",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )
        self._ensure_file_column("identity_metadata_missing", "TEXT")
        self._ensure_checkpoint_column("imported_item_count", "INTEGER")
        self.connection.commit()

    def _ensure_checkpoint_column(self, name: str, definition: str) -> None:
        columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(ia_ingest_checkpoint)")
        }
        if name not in columns:
            self.connection.execute(
                f"ALTER TABLE ia_ingest_checkpoint ADD COLUMN {name} {definition}"
            )

    def _ensure_file_column(self, name: str, definition: str) -> None:
        columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(ia_ingest_file)")
        }
        if name not in columns:
            self.connection.execute(
                f"ALTER TABLE ia_ingest_file ADD COLUMN {name} {definition}"
            )

    def get_checkpoint(self, crawl_key: str) -> Checkpoint | None:
        row = self.connection.execute(
            """
            SELECT crawl_key, query, cursor, completed, imported_item_count, updated_at
            FROM ia_ingest_checkpoint
            WHERE crawl_key = ?
            """,
            (crawl_key,),
        ).fetchone()
        if row is None:
            return None
        return Checkpoint(
            crawl_key=str(row["crawl_key"]),
            query=str(row["query"]),
            cursor=row["cursor"],
            completed=bool(row["completed"]),
            imported_item_count=(
                None
                if row["imported_item_count"] is None
                else int(row["imported_item_count"])
            ),
            updated_at=str(row["updated_at"]),
        )

    def save_checkpoint(
        self,
        *,
        crawl_key: str,
        query: str,
        cursor: str | None,
        completed: bool,
        imported_item_count: int | None = None,
    ) -> None:
        now = utc_now_iso()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ia_ingest_checkpoint (
                    crawl_key,
                    query,
                    cursor,
                    completed,
                    imported_item_count,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(crawl_key) DO UPDATE SET
                    query = excluded.query,
                    cursor = excluded.cursor,
                    completed = excluded.completed,
                    imported_item_count = COALESCE(
                        excluded.imported_item_count,
                        ia_ingest_checkpoint.imported_item_count
                    ),
                    updated_at = excluded.updated_at
                """,
                (
                    crawl_key,
                    query,
                    cursor,
                    int(completed),
                    imported_item_count,
                    now,
                ),
            )

    def upsert_discovered_item(
        self,
        *,
        query: str,
        identifier: str,
        title: str | None,
        mediatype: str | None,
    ) -> None:
        now = utc_now_iso()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ia_ingest_item (
                    identifier,
                    query,
                    title,
                    mediatype,
                    status,
                    first_seen_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, 'discovered', ?, ?)
                ON CONFLICT(identifier) DO UPDATE SET
                    query = excluded.query,
                    title = COALESCE(excluded.title, ia_ingest_item.title),
                    mediatype = COALESCE(excluded.mediatype, ia_ingest_item.mediatype),
                    updated_at = excluded.updated_at
                """,
                (identifier, query, title, mediatype, now, now),
            )

    def get_item(self, identifier: str) -> ItemState | None:
        row = self.connection.execute(
            """
            SELECT identifier, status, attempts, error
            FROM ia_ingest_item
            WHERE identifier = ?
            """,
            (identifier,),
        ).fetchone()
        if row is None:
            return None
        return ItemState(
            identifier=str(row["identifier"]),
            status=str(row["status"]),
            attempts=int(row["attempts"]),
            error=row["error"],
        )

    def item_metadata_already_scanned(self, identifier: str) -> bool:
        row = self.connection.execute(
            """
            SELECT status
            FROM ia_ingest_item
            WHERE identifier = ?
            """,
            (identifier,),
        ).fetchone()
        if row is None:
            return False
        return str(row["status"]) in {"done", "metadata_done"}

    def iter_processable_items(
        self,
        *,
        retry_failed: bool,
        limit: int | None = None,
    ) -> list[ItemState]:
        statuses = ["discovered"]
        if retry_failed:
            statuses.extend(["metadata_failed"])
        placeholders = ", ".join("?" for _ in statuses)
        limit_clause = "" if limit is None else " LIMIT ?"
        params: list[object] = list(statuses)
        if limit is not None:
            params.append(max(0, int(limit)))
        rows = self.connection.execute(
            f"""
            SELECT identifier, status, attempts, error
            FROM ia_ingest_item
            WHERE status IN ({placeholders})
            ORDER BY first_seen_at, identifier
            {limit_clause}
            """,
            params,
        ).fetchall()
        return [
            ItemState(
                identifier=str(row["identifier"]),
                status=str(row["status"]),
                attempts=int(row["attempts"]),
                error=row["error"],
            )
            for row in rows
        ]

    def iter_collection_item_identifiers(self) -> list[str]:
        rows = self.connection.execute(
            """
            SELECT identifier
            FROM ia_ingest_item
            WHERE lower(coalesce(mediatype, '')) = 'collection'
            ORDER BY first_seen_at, identifier
            """
        ).fetchall()
        return [str(row["identifier"]) for row in rows]

    def iter_processable_files(
        self,
        *,
        retry_failed: bool,
        limit: int | None = None,
    ) -> list[QueuedFile]:
        statuses = ["pending", "downloading"]
        if retry_failed:
            statuses.extend(["failed", "skipped"])
        placeholders = ", ".join("?" for _ in statuses)
        limit_clause = "" if limit is None else " LIMIT ?"
        params: list[object] = list(statuses)
        if limit is not None:
            params.append(max(0, int(limit)))
        rows = self.connection.execute(
            f"""
            SELECT
                item_identifier,
                name,
                source,
                format,
                size_bytes,
                md5,
                sha1,
                crc32,
                url,
                status,
                attempts,
                ufid_file_id,
                error,
                needs_downloaded_identity,
                identity_metadata_status,
                identity_metadata_missing
            FROM ia_ingest_file
            WHERE status IN ({placeholders})
            ORDER BY first_seen_at, item_identifier, name
            {limit_clause}
            """,
            params,
        ).fetchall()
        return [_queued_file_from_row(row) for row in rows]

    def mark_item_metadata(self, identifier: str, metadata: Mapping[str, Any]) -> None:
        now = utc_now_iso()
        with self.connection:
            self.connection.execute(
                """
                UPDATE ia_ingest_item
                SET status = 'metadata_done',
                    metadata_json = ?,
                    error = NULL,
                    updated_at = ?
                WHERE identifier = ?
                """,
                (json.dumps(metadata, sort_keys=True), now, identifier),
            )

    def mark_item_status(
        self,
        identifier: str,
        status: str,
        *,
        error: str | None = None,
        increment_attempts: bool = False,
    ) -> None:
        now = utc_now_iso()
        with self.connection:
            self.connection.execute(
                """
                UPDATE ia_ingest_item
                SET status = ?,
                    error = ?,
                    attempts = attempts + ?,
                    updated_at = ?
                WHERE identifier = ?
                """,
                (status, error, 1 if increment_attempts else 0, now, identifier),
            )

    def upsert_file(
        self,
        *,
        item_identifier: str,
        ia_file: IAFile,
        url: str,
        ufid_file_id: int | None = None,
        needs_downloaded_identity: bool = False,
        identity_metadata_status: str = "complete",
        identity_metadata_missing: tuple[str, ...] = (),
    ) -> None:
        now = utc_now_iso()
        missing_json = json.dumps(list(identity_metadata_missing), sort_keys=True)
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ia_ingest_file (
                    item_identifier,
                    name,
                    source,
                    format,
                    size_bytes,
                    md5,
                    sha1,
                    crc32,
                    url,
                    status,
                    ufid_file_id,
                    needs_downloaded_identity,
                    identity_metadata_status,
                    identity_metadata_missing,
                    first_seen_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(item_identifier, name) DO UPDATE SET
                    source = excluded.source,
                    format = excluded.format,
                    size_bytes = excluded.size_bytes,
                    md5 = excluded.md5,
                    sha1 = excluded.sha1,
                    crc32 = excluded.crc32,
                    url = excluded.url,
                    ufid_file_id = COALESCE(excluded.ufid_file_id, ia_ingest_file.ufid_file_id),
                    needs_downloaded_identity = excluded.needs_downloaded_identity,
                    identity_metadata_status = excluded.identity_metadata_status,
                    identity_metadata_missing = excluded.identity_metadata_missing,
                    updated_at = excluded.updated_at
                """,
                (
                    item_identifier,
                    ia_file.name,
                    ia_file.source,
                    ia_file.format,
                    ia_file.size,
                    ia_file.md5,
                    ia_file.sha1,
                    ia_file.crc32,
                    url,
                    ufid_file_id,
                    int(needs_downloaded_identity),
                    identity_metadata_status,
                    missing_json,
                    now,
                    now,
                ),
            )

    def record_file_ufid_identity(
        self,
        item_identifier: str,
        name: str,
        ufid_file_id: int,
    ) -> None:
        now = utc_now_iso()
        with self.connection:
            self.connection.execute(
                """
                UPDATE ia_ingest_file
                SET ufid_file_id = ?,
                    status = CASE
                        WHEN status IN ('failed', 'skipped') THEN 'pending'
                        ELSE status
                    END,
                    error = NULL,
                    updated_at = ?
                WHERE item_identifier = ?
                  AND name = ?
                """,
                (ufid_file_id, now, item_identifier, name),
            )

    def get_file(self, item_identifier: str, name: str) -> FileState | None:
        row = self.connection.execute(
            """
            SELECT item_identifier, name, status, attempts, ufid_file_id, error
            FROM ia_ingest_file
            WHERE item_identifier = ?
              AND name = ?
            """,
            (item_identifier, name),
        ).fetchone()
        if row is None:
            return None
        ufid_file_id = row["ufid_file_id"]
        return FileState(
            item_identifier=str(row["item_identifier"]),
            name=str(row["name"]),
            status=str(row["status"]),
            attempts=int(row["attempts"]),
            ufid_file_id=None if ufid_file_id is None else int(ufid_file_id),
            error=row["error"],
        )

    def mark_file_status(
        self,
        item_identifier: str,
        name: str,
        status: str,
        *,
        ufid_file_id: int | None = None,
        downloaded_path: str | None = None,
        error: str | None = None,
        increment_attempts: bool = False,
    ) -> None:
        now = utc_now_iso()
        with self.connection:
            self.connection.execute(
                """
                UPDATE ia_ingest_file
                SET status = ?,
                    ufid_file_id = COALESCE(?, ufid_file_id),
                    downloaded_path = COALESCE(?, downloaded_path),
                    error = ?,
                    attempts = attempts + ?,
                    updated_at = ?
                WHERE item_identifier = ?
                  AND name = ?
                """,
                (
                    status,
                    ufid_file_id,
                    downloaded_path,
                    error,
                    1 if increment_attempts else 0,
                    now,
                    item_identifier,
                    name,
                ),
            )

    def log_event(
        self,
        level: str,
        message: str,
        *,
        item_identifier: str | None = None,
        file_name: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ia_ingest_event (
                    level,
                    item_identifier,
                    file_name,
                    message,
                    details_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    level,
                    item_identifier,
                    file_name,
                    message,
                    None if details is None else json.dumps(details, sort_keys=True),
                    utc_now_iso(),
                ),
            )

    def stats(self) -> dict[str, dict[str, int]]:
        return {
            "items": self._status_counts("ia_ingest_item"),
            "files": self._status_counts("ia_ingest_file"),
        }

    def _status_counts(self, table: str) -> dict[str, int]:
        rows = self.connection.execute(
            f"SELECT status, count(*) AS count FROM {table} GROUP BY status"
        ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}


def _queued_file_from_row(row: sqlite3.Row) -> QueuedFile:
    size_bytes = row["size_bytes"]
    ufid_file_id = row["ufid_file_id"]
    missing = _decode_missing_identity(row["identity_metadata_missing"])
    return QueuedFile(
        item_identifier=str(row["item_identifier"]),
        name=str(row["name"]),
        source=row["source"],
        format=row["format"],
        size_bytes=None if size_bytes is None else int(size_bytes),
        md5=row["md5"],
        sha1=row["sha1"],
        crc32=row["crc32"],
        url=row["url"],
        status=str(row["status"]),
        attempts=int(row["attempts"]),
        ufid_file_id=None if ufid_file_id is None else int(ufid_file_id),
        error=row["error"],
        needs_downloaded_identity=bool(row["needs_downloaded_identity"]),
        identity_metadata_status=str(row["identity_metadata_status"]),
        identity_metadata_missing=missing,
    )


def _decode_missing_identity(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, list):
        return ()
    return tuple(str(item) for item in payload if item)
