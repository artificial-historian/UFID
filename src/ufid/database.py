from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Iterable, Mapping, Sequence

from ufid.auth import (
    DEFAULT_SESSION_SECONDS,
    AuthenticatedUser,
    hash_password,
    hash_session_token,
    new_session_token,
    parse_timestamp,
    session_expiry_iso,
    utc_now,
    utc_now_iso,
    verify_password,
)


LOGGER = logging.getLogger(__name__)
SQLITE_BUSY_TIMEOUT_MS = 30_000
SQLITE_CONNECT_TIMEOUT_SECONDS = SQLITE_BUSY_TIMEOUT_MS / 1000
REQUIRED_HASH_ALGORITHMS = ("crc32", "md5", "sha1")
OPTIONAL_HASH_ALGORITHMS = ("sha256", "blake3")
SUPPORTED_HASH_ALGORITHMS = REQUIRED_HASH_ALGORITHMS + OPTIONAL_HASH_ALGORITHMS
HASH_HEX_LENGTHS = {
    "crc32": 8,
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "blake3": 64,
}
GOLDRUSH_ALERT_COLUMNS = (
    "name",
    "description",
    "size_bytes",
    *SUPPORTED_HASH_ALGORITHMS,
    "source_type",
    "source_name",
    "source_detail",
    "fingerprint",
)
FILE_LIST_SORT_COLUMNS = {
    "id": "f.id",
    "name": (
        "COALESCE((SELECT fm.value FROM ufid_file_meta fm "
        "WHERE fm.file_id = f.id AND fm.name = 'filename' "
        "ORDER BY fm.added_at, fm.id LIMIT 1), '') COLLATE NOCASE"
    ),
    "size": "f.size_bytes",
    "crc32": "f.crc32",
    "md5": "f.md5",
    "sha1": "f.sha1",
    "sha256": "COALESCE(f.sha256, '')",
    "blake3": "COALESCE(f.blake3, '')",
}
IDENTITY_CONFLICT_TYPES = (
    "optional_hash_mismatch",
    "required_hash_overlap",
)
ALLOWED_METADATA_TYPES = (
    "text",
    "image",
    "url",
    "json",
    "number",
    "date",
    "binary",
    "other",
)
_INITIALIZE_LOCK = Lock()
_INITIALIZED_DATABASES: set[str] = set()


SQLITE_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS ufid_file (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    crc32 TEXT NOT NULL CHECK (
        length(crc32) = 8 AND crc32 = lower(crc32) AND crc32 NOT GLOB '*[^0-9a-f]*'
    ),
    md5 TEXT NOT NULL CHECK (
        length(md5) = 32 AND md5 = lower(md5) AND md5 NOT GLOB '*[^0-9a-f]*'
    ),
    sha1 TEXT NOT NULL CHECK (
        length(sha1) = 40 AND sha1 = lower(sha1) AND sha1 NOT GLOB '*[^0-9a-f]*'
    ),
    sha256 TEXT CHECK (
        sha256 IS NULL OR (
            length(sha256) = 64
            AND sha256 = lower(sha256)
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    blake3 TEXT CHECK (
        blake3 IS NULL OR (
            length(blake3) = 64
            AND blake3 = lower(blake3)
            AND blake3 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    UNIQUE (size_bytes, crc32, md5, sha1)
);

CREATE INDEX IF NOT EXISTS idx_ufid_file_crc32
ON ufid_file (crc32);

CREATE INDEX IF NOT EXISTS idx_ufid_file_md5
ON ufid_file (md5);

CREATE INDEX IF NOT EXISTS idx_ufid_file_sha1
ON ufid_file (sha1);

CREATE INDEX IF NOT EXISTS idx_ufid_file_sha256
ON ufid_file (sha256);

CREATE INDEX IF NOT EXISTS idx_ufid_file_blake3
ON ufid_file (blake3);

CREATE TABLE IF NOT EXISTS ufid_file_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    metadata_type TEXT NOT NULL CHECK (
        metadata_type IN ('text', 'image', 'url', 'json', 'number', 'date', 'binary', 'other')
    ),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    value TEXT NOT NULL,
    notes TEXT,
    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ufid_file_meta_unique
ON ufid_file_meta (
    file_id,
    metadata_type,
    name,
    value,
    COALESCE(notes, '')
);

CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_file_id
ON ufid_file_meta (file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_name
ON ufid_file_meta (name);

CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_type
ON ufid_file_meta (metadata_type);

CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_added_at
ON ufid_file_meta (added_at);

CREATE TABLE IF NOT EXISTS ufid_archive_member (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_file_id INTEGER NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    child_file_id INTEGER REFERENCES ufid_file(id) ON DELETE CASCADE,
    archive_path TEXT,
    CHECK (child_file_id IS NOT NULL OR archive_path IS NOT NULL),
    UNIQUE (parent_file_id, child_file_id, archive_path)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ufid_archive_member_unique
ON ufid_archive_member (
    parent_file_id,
    COALESCE(child_file_id, -1),
    COALESCE(archive_path, '')
);

CREATE INDEX IF NOT EXISTS idx_ufid_archive_member_parent
ON ufid_archive_member (parent_file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_archive_member_child
ON ufid_archive_member (child_file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_archive_member_path
ON ufid_archive_member (archive_path);

CREATE TABLE IF NOT EXISTS ufid_identity_conflict (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    related_file_id INTEGER REFERENCES ufid_file(id) ON DELETE CASCADE,
    conflict_type TEXT NOT NULL CHECK (
        conflict_type IN ('optional_hash_mismatch', 'required_hash_overlap')
    ),
    algorithm TEXT NOT NULL,
    existing_value TEXT,
    incoming_value TEXT NOT NULL,
    incoming_size_bytes INTEGER NOT NULL CHECK (incoming_size_bytes >= 0),
    incoming_crc32 TEXT NOT NULL,
    incoming_md5 TEXT NOT NULL,
    incoming_sha1 TEXT NOT NULL,
    notes TEXT,
    logged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ufid_identity_conflict_unique
ON ufid_identity_conflict (
    file_id,
    COALESCE(related_file_id, -1),
    conflict_type,
    algorithm,
    COALESCE(existing_value, ''),
    incoming_value,
    incoming_size_bytes,
    incoming_crc32,
    incoming_md5,
    incoming_sha1,
    COALESCE(notes, '')
);

CREATE INDEX IF NOT EXISTS idx_ufid_identity_conflict_file
ON ufid_identity_conflict (file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_identity_conflict_related
ON ufid_identity_conflict (related_file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_identity_conflict_type
ON ufid_identity_conflict (conflict_type);

CREATE TABLE IF NOT EXISTS ufid_source (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ufid_file_source (
    file_id INTEGER NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES ufid_source(id),
    external_reference TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (file_id, source_id, external_reference)
);

CREATE TABLE IF NOT EXISTS ufid_goldrush_alert (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0),
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    crc32 TEXT CHECK (
        crc32 IS NULL OR (
            length(crc32) = 8
            AND crc32 = lower(crc32)
            AND crc32 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    md5 TEXT CHECK (
        md5 IS NULL OR (
            length(md5) = 32
            AND md5 = lower(md5)
            AND md5 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    sha1 TEXT CHECK (
        sha1 IS NULL OR (
            length(sha1) = 40
            AND sha1 = lower(sha1)
            AND sha1 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    sha256 TEXT CHECK (
        sha256 IS NULL OR (
            length(sha256) = 64
            AND sha256 = lower(sha256)
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    blake3 TEXT CHECK (
        blake3 IS NULL OR (
            length(blake3) = 64
            AND blake3 = lower(blake3)
            AND blake3 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    source_type TEXT,
    source_name TEXT,
    source_detail TEXT,
    fingerprint TEXT NOT NULL UNIQUE CHECK (length(trim(fingerprint)) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        crc32 IS NOT NULL
        OR md5 IS NOT NULL
        OR sha1 IS NOT NULL
        OR sha256 IS NOT NULL
        OR blake3 IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_crc32
ON ufid_goldrush_alert (crc32);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_md5
ON ufid_goldrush_alert (md5);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_sha1
ON ufid_goldrush_alert (sha1);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_sha256
ON ufid_goldrush_alert (sha256);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_blake3
ON ufid_goldrush_alert (blake3);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_size
ON ufid_goldrush_alert (size_bytes);

CREATE INDEX IF NOT EXISTS idx_ufid_goldrush_alert_source
ON ufid_goldrush_alert (source_name);

CREATE TABLE IF NOT EXISTS ufid_user_account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE CHECK (
        length(trim(username)) > 0 AND username = lower(username)
    ),
    password_hash TEXT NOT NULL,
    display_name TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS ufid_role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS ufid_user_role (
    user_id INTEGER NOT NULL REFERENCES ufid_user_account(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES ufid_role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS ufid_session (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES ufid_user_account(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE CHECK (
        length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT,
    user_agent TEXT,
    ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_ufid_session_token_hash
ON ufid_session (token_hash);

CREATE INDEX IF NOT EXISTS idx_ufid_session_user_id
ON ufid_session (user_id);

CREATE INDEX IF NOT EXISTS idx_ufid_session_expires_at
ON ufid_session (expires_at);

INSERT OR IGNORE INTO ufid_role (name) VALUES
    ('reader'),
    ('contributor'),
    ('curator'),
    ('admin');
"""


class IdentityConflict(ValueError):
    def __init__(
        self,
        message: str,
        *,
        file_id: int | None = None,
        conflict_type: str | None = None,
    ) -> None:
        super().__init__(message)
        self.file_id = file_id
        self.conflict_type = conflict_type


@dataclass(frozen=True)
class UpsertResult:
    file_id: int
    created: bool
    enriched: bool


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=SQLITE_CONNECT_TIMEOUT_SECONDS)
    connection.row_factory = sqlite3.Row
    _configure_connection(connection)
    _initialize_once(connection, path)
    return connection


def _configure_connection(connection: sqlite3.Connection) -> None:
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA foreign_keys = ON")


def _initialize_once(connection: sqlite3.Connection, path: Path) -> None:
    key = str(path.resolve())
    if key in _INITIALIZED_DATABASES:
        return
    with _INITIALIZE_LOCK:
        if key in _INITIALIZED_DATABASES:
            return
        initialize(connection)
        _INITIALIZED_DATABASES.add(key)


def initialize(connection: sqlite3.Connection) -> None:
    _reject_legacy_schema(connection)
    connection.executescript(SQLITE_SCHEMA)
    connection.commit()


def create_user(
    connection: sqlite3.Connection,
    *,
    username: str,
    password: str,
    roles: Sequence[str] = ("reader",),
    display_name: str | None = None,
) -> dict[str, Any]:
    normalized_username = _normalize_username(username)
    normalized_roles = _normalize_roles(roles)
    password_hash = hash_password(password)
    with connection:
        cursor = connection.execute(
            """
            INSERT INTO ufid_user_account (username, password_hash, display_name)
            VALUES (?, ?, ?)
            """,
            (normalized_username, password_hash, display_name),
        )
        user_id = int(cursor.lastrowid)
        _set_user_roles(connection, user_id=user_id, roles=normalized_roles)
    user = get_user_by_username(connection, normalized_username)
    assert user is not None
    return user


def authenticate_user(
    connection: sqlite3.Connection,
    *,
    username: str,
    password: str,
) -> dict[str, Any] | None:
    user = get_user_by_username(connection, username)
    if user is None or user.get("disabled_at"):
        return None
    row = connection.execute(
        "SELECT password_hash FROM ufid_user_account WHERE id = ?",
        (user["id"],),
    ).fetchone()
    if row is None or not verify_password(password, str(row["password_hash"])):
        return None
    return user


def create_session(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    seconds: int = DEFAULT_SESSION_SECONDS,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> tuple[str, AuthenticatedUser]:
    token = new_session_token()
    token_hash = hash_session_token(token)
    now = utc_now_iso()
    expires_at = session_expiry_iso(seconds)
    with connection:
        cursor = connection.execute(
            """
            INSERT INTO ufid_session (
                user_id,
                token_hash,
                created_at,
                expires_at,
                last_seen_at,
                user_agent,
                ip_address
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, token_hash, now, expires_at, now, user_agent, ip_address),
        )
        session_id = int(cursor.lastrowid)
    user = get_authenticated_user(connection, token)
    assert user is not None
    return token, AuthenticatedUser(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        roles=user.roles,
        session_id=session_id,
        expires_at=expires_at,
    )


def get_authenticated_user(
    connection: sqlite3.Connection,
    token: str | None,
) -> AuthenticatedUser | None:
    if not token:
        return None
    token_hash = hash_session_token(token)
    row = connection.execute(
        """
        SELECT
            s.id AS session_id,
            s.expires_at,
            s.revoked_at,
            u.id AS user_id,
            u.username,
            u.display_name,
            u.disabled_at
        FROM ufid_session s
        JOIN ufid_user_account u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()
    if row is None or row["revoked_at"] or row["disabled_at"]:
        return None
    if parse_timestamp(row["expires_at"]) <= utc_now():
        return None

    now = utc_now_iso()
    with connection:
        connection.execute(
            "UPDATE ufid_session SET last_seen_at = ? WHERE id = ?",
            (now, row["session_id"]),
        )
    return AuthenticatedUser(
        id=int(row["user_id"]),
        username=str(row["username"]),
        display_name=row["display_name"],
        roles=tuple(get_user_roles(connection, int(row["user_id"]))),
        session_id=int(row["session_id"]),
        expires_at=str(row["expires_at"]),
    )


def revoke_session(connection: sqlite3.Connection, token: str | None) -> bool:
    if not token:
        return False
    token_hash = hash_session_token(token)
    with connection:
        cursor = connection.execute(
            """
            UPDATE ufid_session
            SET revoked_at = ?
            WHERE token_hash = ?
              AND revoked_at IS NULL
            """,
            (utc_now_iso(), token_hash),
        )
    return cursor.rowcount > 0


def get_user_by_username(
    connection: sqlite3.Connection,
    username: str,
) -> dict[str, Any] | None:
    normalized_username = _normalize_username(username)
    row = connection.execute(
        """
        SELECT id, username, display_name, created_at, disabled_at
        FROM ufid_user_account
        WHERE lower(username) = lower(?)
        """,
        (normalized_username,),
    ).fetchone()
    if row is None:
        return None
    user = dict(row)
    user["roles"] = get_user_roles(connection, int(row["id"]))
    return user


def get_user_roles(connection: sqlite3.Connection, user_id: int) -> list[str]:
    rows = connection.execute(
        """
        SELECT r.name
        FROM ufid_user_role ur
        JOIN ufid_role r ON r.id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY r.name
        """,
        (user_id,),
    ).fetchall()
    return [str(row["name"]) for row in rows]


def _reject_legacy_schema(connection: sqlite3.Connection) -> None:
    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    if "ufid_file" not in tables:
        return

    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(ufid_file)").fetchall()
    }
    if {"crc32", "md5", "sha1"}.issubset(columns):
        return

    raise RuntimeError(
        "Existing UFID database uses the old prototype schema. "
        "Create a new SQLite database for the flat ufid_file schema."
    )


def _normalize_username(username: str) -> str:
    normalized = str(username or "").strip().lower()
    if not normalized:
        raise ValueError("username is required")
    if len(normalized) > 150:
        raise ValueError("username is too long")
    return normalized


def _normalize_roles(roles: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(role).strip().lower() for role in roles if role))
    if not normalized:
        raise ValueError("at least one role is required")
    allowed = {"reader", "contributor", "curator", "admin"}
    unknown = sorted(set(normalized) - allowed)
    if unknown:
        raise ValueError(f"unknown roles: {', '.join(unknown)}")
    return normalized


def _set_user_roles(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    roles: Sequence[str],
) -> None:
    for role in roles:
        row = connection.execute(
            "SELECT id FROM ufid_role WHERE name = ?",
            (role,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown role: {role}")
        connection.execute(
            """
            INSERT OR IGNORE INTO ufid_user_role (user_id, role_id)
            VALUES (?, ?)
            """,
            (user_id, int(row["id"])),
        )


def find_file_by_hash(
    connection: sqlite3.Connection,
    algorithm: str,
    hash_value: str,
    size_bytes: int | None = None,
) -> dict[str, Any] | None:
    records = find_files_by_hash(
        connection,
        algorithm,
        hash_value,
        size_bytes=size_bytes,
    )
    if not records:
        return None
    return records[0]


def find_files_by_hash(
    connection: sqlite3.Connection,
    algorithm: str,
    hash_value: str,
    size_bytes: int | None = None,
) -> list[dict[str, Any]]:
    column = _hash_column(algorithm)
    size_filter = "AND size_bytes = ?" if size_bytes is not None else ""
    params: tuple[Any, ...]
    if size_bytes is None:
        params = (hash_value,)
    else:
        params = (hash_value, size_bytes)

    rows = connection.execute(
        f"""
        SELECT id
        FROM ufid_file
        WHERE {column} IS NOT NULL
          AND lower({column}) = lower(?)
          {size_filter}
        ORDER BY id DESC
        """,
        params,
    ).fetchall()
    return [
        record
        for row in rows
        if (record := get_file(connection, int(row["id"]))) is not None
    ]


def get_file(connection: sqlite3.Connection, file_id: int) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM ufid_file WHERE id = ?",
        (file_id,),
    ).fetchone()
    if row is None:
        return None

    metadata_rows = connection.execute(
        """
        SELECT id, file_id, metadata_type, name, value, notes, added_at
        FROM ufid_file_meta
        WHERE file_id = ?
        ORDER BY added_at, id
        """,
        (file_id,),
    ).fetchall()

    result = dict(row)
    result["hashes"] = {
        algorithm: result.get(algorithm)
        for algorithm in SUPPORTED_HASH_ALGORITHMS
    }
    result["metadata"] = [dict(item) for item in metadata_rows]
    result["archive_members"] = list_archive_members(connection, file_id)
    result["identity_conflicts"] = list_identity_conflicts(connection, file_id)
    result.update(_derived_metadata_fields(result["metadata"]))
    return result


def list_archive_members(
    connection: sqlite3.Connection,
    parent_file_id: int,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT id, parent_file_id, child_file_id, archive_path
        FROM ufid_archive_member
        WHERE parent_file_id = ?
        ORDER BY archive_path, id
        """,
        (parent_file_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def add_archive_member(
    connection: sqlite3.Connection,
    *,
    parent_file_id: int,
    child_file_id: int | None,
    archive_path: str | None,
) -> bool:
    if child_file_id is None and not archive_path:
        raise ValueError("archive_path is required when child_file_id is NULL")

    existing = connection.execute(
        """
        SELECT id
        FROM ufid_archive_member
        WHERE parent_file_id = ?
          AND (
              child_file_id = ?
              OR (child_file_id IS NULL AND ? IS NULL)
          )
          AND (
              archive_path = ?
              OR (archive_path IS NULL AND ? IS NULL)
          )
        """,
        (
            parent_file_id,
            child_file_id,
            child_file_id,
            archive_path,
            archive_path,
        ),
    ).fetchone()
    if existing is not None:
        return False

    with connection:
        connection.execute(
            """
            INSERT INTO ufid_archive_member (
                parent_file_id,
                child_file_id,
                archive_path
            )
            VALUES (?, ?, ?)
            """,
            (parent_file_id, child_file_id, archive_path),
        )
    return True


def list_identity_conflicts(
    connection: sqlite3.Connection,
    file_id: int,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT
            id,
            file_id,
            related_file_id,
            conflict_type,
            algorithm,
            existing_value,
            incoming_value,
            incoming_size_bytes,
            incoming_crc32,
            incoming_md5,
            incoming_sha1,
            notes,
            logged_at
        FROM ufid_identity_conflict
        WHERE file_id = ?
           OR related_file_id = ?
        ORDER BY logged_at, id
        """,
        (file_id, file_id),
    ).fetchall()
    return [dict(row) for row in rows]


def record_identity_conflict(
    connection: sqlite3.Connection,
    *,
    file_id: int,
    conflict_type: str,
    algorithm: str,
    existing_value: str | None,
    incoming_value: str,
    incoming_size_bytes: int,
    incoming_hashes: Mapping[str, str],
    related_file_id: int | None = None,
    notes: str | None = None,
) -> bool:
    if conflict_type not in IDENTITY_CONFLICT_TYPES:
        allowed = ", ".join(IDENTITY_CONFLICT_TYPES)
        raise ValueError(f"conflict_type must be one of: {allowed}")

    normalized_algorithm = _hash_column(algorithm)
    _validate_required_identity(incoming_size_bytes, incoming_hashes)
    existing = connection.execute(
        """
        SELECT id
        FROM ufid_identity_conflict
        WHERE file_id = ?
          AND (
              related_file_id = ?
              OR (related_file_id IS NULL AND ? IS NULL)
          )
          AND conflict_type = ?
          AND algorithm = ?
          AND COALESCE(existing_value, '') = COALESCE(?, '')
          AND incoming_value = ?
          AND incoming_size_bytes = ?
          AND incoming_crc32 = ?
          AND incoming_md5 = ?
          AND incoming_sha1 = ?
          AND COALESCE(notes, '') = COALESCE(?, '')
        """,
        (
            file_id,
            related_file_id,
            related_file_id,
            conflict_type,
            normalized_algorithm,
            existing_value,
            incoming_value,
            incoming_size_bytes,
            incoming_hashes["crc32"],
            incoming_hashes["md5"],
            incoming_hashes["sha1"],
            notes,
        ),
    ).fetchone()
    if existing is not None:
        return False

    connection.execute(
        """
        INSERT INTO ufid_identity_conflict (
            file_id,
            related_file_id,
            conflict_type,
            algorithm,
            existing_value,
            incoming_value,
            incoming_size_bytes,
            incoming_crc32,
            incoming_md5,
            incoming_sha1,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            related_file_id,
            conflict_type,
            normalized_algorithm,
            existing_value,
            incoming_value,
            incoming_size_bytes,
            incoming_hashes["crc32"],
            incoming_hashes["md5"],
            incoming_hashes["sha1"],
            notes,
        ),
    )
    LOGGER.warning(
        "Recorded UFID identity conflict: type=%s file_id=%s related_file_id=%s algorithm=%s",
        conflict_type,
        file_id,
        related_file_id,
        normalized_algorithm,
    )
    return True


def add_file_metadata(
    connection: sqlite3.Connection,
    *,
    file_id: int,
    metadata: Mapping[str, str] | Sequence[Mapping[str, Any]],
) -> bool:
    metadata_entries = list(
        _metadata_entries(
            display_name=None,
            description=None,
            content_type=None,
            metadata=metadata,
        )
    )
    if not metadata_entries:
        return False

    enriched = False
    with connection:
        for item in metadata_entries:
            if _insert_metadata_if_new(connection, file_id, item):
                enriched = True
    return enriched


def create_goldrush_alert(
    connection: sqlite3.Connection,
    *,
    name: str,
    description: str,
    hashes: Mapping[str, str | None],
    size_bytes: int | str | None = None,
    source_type: str | None = None,
    source_name: str | None = None,
    source_detail: str | None = None,
) -> dict[str, Any]:
    normalized = _normalize_goldrush_alert(
        {
            "name": name,
            "description": description,
            "size_bytes": size_bytes,
            "hashes": hashes,
            "source_type": source_type,
            "source_name": source_name,
            "source_detail": source_detail,
        }
    )
    with connection:
        created = _insert_goldrush_alert(connection, normalized)
    alert = _get_goldrush_alert_by_fingerprint(connection, normalized["fingerprint"])
    assert alert is not None
    return {"alert": alert, "created": created}


def import_goldrush_alerts(
    connection: sqlite3.Connection,
    alerts: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    received = list(alerts)
    normalized_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, alert in enumerate(received):
        try:
            normalized_rows.append(_normalize_goldrush_alert(alert))
        except ValueError as exc:
            errors.append(
                {
                    "index": index,
                    "name": str(alert.get("name") or ""),
                    "error": str(exc),
                }
            )

    created = 0
    with connection:
        for row in normalized_rows:
            if _insert_goldrush_alert(connection, row):
                created += 1

    return {
        "received": len(received),
        "valid": len(normalized_rows),
        "created": created,
        "skipped": len(normalized_rows) - created,
        "errors": errors,
    }


def list_goldrush_alerts(
    connection: sqlite3.Connection,
    *,
    limit: int = 200,
    offset: int = 0,
    query: str | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = min(max(limit, 1), 200)
    bounded_offset = max(offset, 0)
    where_sql, params = _goldrush_alert_filter(query)
    rows = connection.execute(
        f"""
        SELECT *
        FROM ufid_goldrush_alert a
        {where_sql}
        ORDER BY a.id DESC
        LIMIT ? OFFSET ?
        """,
        (*params, bounded_limit, bounded_offset),
    ).fetchall()
    return [_goldrush_alert_row(row) for row in rows]


def count_goldrush_alerts(
    connection: sqlite3.Connection,
    *,
    query: str | None = None,
) -> int:
    where_sql, params = _goldrush_alert_filter(query)
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM ufid_goldrush_alert a
        {where_sql}
        """,
        params,
    ).fetchone()
    return int(row["total"] if row is not None else 0)


def list_goldrush_alert_sources(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        f"""
        WITH goldrush_alert_source AS (
            SELECT
                {_goldrush_alert_source_key_sql()} AS source_key,
                CASE
                    WHEN COALESCE(a.source_type, '') = ''
                     AND COALESCE(a.source_name, '') = ''
                    THEN 'Manual'
                    ELSE COALESCE(NULLIF(a.source_name, ''), NULLIF(a.source_type, ''), 'Imported')
                END AS label,
                NULLIF(a.source_type, '') AS source_type,
                NULLIF(a.source_name, '') AS source_name
            FROM ufid_goldrush_alert a
        )
        SELECT
            source_key,
            label,
            source_type,
            source_name,
            COUNT(*) AS alert_count
        FROM goldrush_alert_source
        GROUP BY source_key, label, source_type, source_name
        ORDER BY
            CASE WHEN source_key = 'manual' THEN 0 ELSE 1 END,
            lower(label),
            source_key
        """
    ).fetchall()
    return [_goldrush_alert_source_row(row) for row in rows]


def list_goldrush_matches(
    connection: sqlite3.Connection,
    *,
    limit: int = 200,
    offset: int = 0,
    query: str | None = None,
    source_keys: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = min(max(limit, 1), 200)
    bounded_offset = max(offset, 0)
    filter_sql, params = _goldrush_match_filter(query, source_keys=source_keys)
    rows = connection.execute(
        f"""
        {_goldrush_match_cte_sql(include_sources=True)}
        SELECT
            a.id AS alert_id,
            a.name AS alert_name,
            a.description AS alert_description,
            a.size_bytes AS alert_size_bytes,
            a.crc32 AS alert_crc32,
            a.md5 AS alert_md5,
            a.sha1 AS alert_sha1,
            a.sha256 AS alert_sha256,
            a.blake3 AS alert_blake3,
            a.source_type AS alert_source_type,
            a.source_name AS alert_source_name,
            a.source_detail AS alert_source_detail,
            a.created_at AS alert_created_at,
            f.id AS file_id,
            f.size_bytes AS file_size_bytes,
            f.crc32 AS file_crc32,
            f.md5 AS file_md5,
            f.sha1 AS file_sha1,
            f.sha256 AS file_sha256,
            f.blake3 AS file_blake3,
            COALESCE((
                SELECT fm.value
                FROM ufid_file_meta fm
                WHERE fm.file_id = f.id
                  AND fm.name = 'filename'
                ORDER BY fm.added_at, fm.id
                LIMIT 1
            ), '') AS file_display_name,
            (
                SELECT fm.value
                FROM ufid_file_meta fm
                WHERE fm.file_id = f.id
                  AND fm.name = 'content_type'
                ORDER BY fm.added_at, fm.id
                LIMIT 1
            ) AS file_content_type,
            m.matched_crc32,
            m.matched_md5,
            m.matched_sha1,
            m.matched_sha256,
            m.matched_blake3,
            CASE WHEN a.size_bytes IS NOT NULL THEN 1 ELSE 0 END AS size_matched,
            s.source_file_id,
            s.ia_identifier,
            s.ia_item_url,
            s.ia_file_url,
            s.ia_file_name
        {_goldrush_match_from_sql(include_sources=True)}
        {filter_sql}
        ORDER BY a.id DESC, f.id DESC
        LIMIT ? OFFSET ?
        """,
        (*params, bounded_limit, bounded_offset),
    ).fetchall()
    return [_goldrush_match_row(row) for row in rows]


def count_goldrush_matches(
    connection: sqlite3.Connection,
    *,
    query: str | None = None,
    source_keys: Sequence[str] | None = None,
) -> int:
    filter_sql, params = _goldrush_match_filter(query, source_keys=source_keys)
    row = connection.execute(
        f"""
        {_goldrush_match_cte_sql()}
        SELECT COUNT(*) AS total
        {_goldrush_match_from_sql()}
        {filter_sql}
        """,
        params,
    ).fetchone()
    return int(row["total"] if row is not None else 0)


def list_files(
    connection: sqlite3.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    query: str | None = None,
    sort_by: str = "id",
    sort_direction: str = "desc",
) -> list[dict[str, Any]]:
    bounded_limit = min(max(limit, 1), 200)
    bounded_offset = max(offset, 0)
    sort_sql, direction_sql = _file_list_sort(sort_by, sort_direction)
    tie_breaker = "" if sort_by == "id" else ", f.id DESC"
    where_sql, params = _file_list_filter(query)
    rows = connection.execute(
        f"""
        SELECT f.id
        FROM ufid_file f
        {where_sql}
        ORDER BY {sort_sql} {direction_sql}{tie_breaker}
        LIMIT ? OFFSET ?
        """,
        (*params, bounded_limit, bounded_offset),
    ).fetchall()

    return [
        record
        for row in rows
        if (record := get_file(connection, int(row["id"]))) is not None
    ]


def count_files(
    connection: sqlite3.Connection,
    *,
    query: str | None = None,
) -> int:
    where_sql, params = _file_list_filter(query)
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM ufid_file f
        {where_sql}
        """,
        params,
    ).fetchone()
    return int(row["total"] if row is not None else 0)


def upsert_file_identity(
    connection: sqlite3.Connection,
    *,
    display_name: str | None,
    size_bytes: int | None,
    hashes: Mapping[str, str | None],
    description: str | None = None,
    content_type: str | None = None,
    metadata: Mapping[str, str] | Sequence[Mapping[str, Any]] | None = None,
) -> UpsertResult:
    normalized_hashes = normalize_hashes(hashes)
    _validate_required_identity(size_bytes, normalized_hashes)
    assert size_bytes is not None

    created = False
    enriched = False
    deferred_conflict: IdentityConflict | None = None

    with connection:
        existing = _find_identity_row(connection, size_bytes, normalized_hashes)
        if existing is None:
            required_overlaps = _find_required_hash_overlaps(
                connection,
                size_bytes,
                normalized_hashes,
            )
            cursor = connection.execute(
                """
                INSERT INTO ufid_file (
                    size_bytes,
                    crc32,
                    md5,
                    sha1,
                    sha256,
                    blake3
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    size_bytes,
                    normalized_hashes["crc32"],
                    normalized_hashes["md5"],
                    normalized_hashes["sha1"],
                    normalized_hashes.get("sha256"),
                    normalized_hashes.get("blake3"),
                ),
            )
            file_id = int(cursor.lastrowid)
            created = True
            _record_required_hash_overlaps(
                connection,
                incoming_file_id=file_id,
                incoming_size_bytes=size_bytes,
                incoming_hashes=normalized_hashes,
                overlaps=required_overlaps,
            )
        else:
            file_id = int(existing["id"])
            mismatches = []
            for algorithm in OPTIONAL_HASH_ALGORITHMS:
                incoming = normalized_hashes.get(algorithm)
                current = existing[algorithm]
                if incoming is None or current is None:
                    continue
                if str(current).lower() != incoming:
                    mismatches.append((algorithm, str(current), incoming))

            if mismatches:
                for algorithm, current, incoming in mismatches:
                    record_identity_conflict(
                        connection,
                        file_id=file_id,
                        conflict_type="optional_hash_mismatch",
                        algorithm=algorithm,
                        existing_value=current,
                        incoming_value=incoming,
                        incoming_size_bytes=size_bytes,
                        incoming_hashes=normalized_hashes,
                        notes=(
                            "Same required identity tuple was observed with a "
                            f"different {algorithm} value"
                        ),
                    )
                algorithms = ", ".join(item[0] for item in mismatches)
                deferred_conflict = IdentityConflict(
                    f"Optional hash conflict for UFID {file_id}: {algorithms}",
                    file_id=file_id,
                    conflict_type="optional_hash_mismatch",
                )

            if deferred_conflict is None:
                metadata_entries = list(
                    _metadata_entries(
                        display_name=display_name,
                        description=description,
                        content_type=content_type,
                        metadata=metadata,
                    )
                )
            else:
                metadata_entries = []

            updates: dict[str, str] = {}
            if deferred_conflict is None:
                for algorithm in OPTIONAL_HASH_ALGORITHMS:
                    incoming = normalized_hashes.get(algorithm)
                    current = existing[algorithm]
                    if incoming is None:
                        continue
                    if current is None:
                        updates[algorithm] = incoming

            if updates:
                assignments = ", ".join(f"{key} = ?" for key in updates)
                connection.execute(
                    f"UPDATE ufid_file SET {assignments} WHERE id = ?",
                    [*updates.values(), file_id],
                )
                enriched = True

        if existing is None:
            metadata_entries = list(
                _metadata_entries(
                    display_name=display_name,
                    description=description,
                    content_type=content_type,
                    metadata=metadata,
                )
            )
        for item in metadata_entries:
            if _insert_metadata_if_new(connection, file_id, item):
                enriched = not created or enriched

    if deferred_conflict is not None:
        raise deferred_conflict

    return UpsertResult(file_id=file_id, created=created, enriched=enriched)


def normalize_hashes(hashes: Mapping[str, str | None]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for algorithm, hash_value in hashes.items():
        if hash_value is None:
            continue
        normalized_algorithm = str(algorithm).lower().replace("-", "")
        if normalized_algorithm == "sha1":
            normalized_algorithm = "sha1"
        if normalized_algorithm not in SUPPORTED_HASH_ALGORITHMS:
            continue
        value = str(hash_value).strip().lower()
        if value:
            normalized[normalized_algorithm] = value
    return normalized


def _validate_required_identity(
    size_bytes: int | None,
    hashes: Mapping[str, str],
) -> None:
    missing_required = [
        algorithm
        for algorithm in REQUIRED_HASH_ALGORITHMS
        if algorithm not in hashes
    ]
    if missing_required:
        joined = ", ".join(missing_required)
        raise ValueError(f"Required hashes are missing: {joined}")
    if size_bytes is None:
        raise ValueError("Exact file size is required")
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
        raise ValueError("Exact file size must be a non-negative integer")
    _validate_hash_values(hashes)


def _validate_hash_values(hashes: Mapping[str, str]) -> None:
    hex_digits = set("0123456789abcdef")
    for algorithm, value in hashes.items():
        expected_length = HASH_HEX_LENGTHS.get(algorithm)
        if expected_length is None:
            continue
        if len(value) != expected_length:
            raise ValueError(
                f"{algorithm} must be exactly {expected_length} hexadecimal characters"
            )
        if any(character not in hex_digits for character in value):
            raise ValueError(f"{algorithm} must contain only hexadecimal characters")


def _find_identity_row(
    connection: sqlite3.Connection,
    size_bytes: int,
    hashes: Mapping[str, str],
) -> sqlite3.Row | None:
    row = connection.execute(
        """
        SELECT *
        FROM ufid_file
        WHERE size_bytes = ?
          AND lower(crc32) = lower(?)
          AND lower(md5) = lower(?)
          AND lower(sha1) = lower(?)
        """,
        (size_bytes, hashes["crc32"], hashes["md5"], hashes["sha1"]),
    ).fetchone()
    return row


def _find_required_hash_overlaps(
    connection: sqlite3.Connection,
    size_bytes: int,
    hashes: Mapping[str, str],
) -> list[sqlite3.Row]:
    rows = connection.execute(
        """
        SELECT id, size_bytes, crc32, md5, sha1
        FROM ufid_file
        WHERE size_bytes = ?
          AND (
              lower(crc32) = lower(?)
           OR lower(md5) = lower(?)
           OR lower(sha1) = lower(?)
          )
          AND NOT (
              lower(crc32) = lower(?)
          AND lower(md5) = lower(?)
          AND lower(sha1) = lower(?)
          )
        """,
        (
            size_bytes,
            hashes["crc32"],
            hashes["md5"],
            hashes["sha1"],
            hashes["crc32"],
            hashes["md5"],
            hashes["sha1"],
        ),
    ).fetchall()
    return list(rows)


def _record_required_hash_overlaps(
    connection: sqlite3.Connection,
    *,
    incoming_file_id: int,
    incoming_size_bytes: int,
    incoming_hashes: Mapping[str, str],
    overlaps: Sequence[sqlite3.Row],
) -> None:
    for row in overlaps:
        existing_file_id = int(row["id"])
        matched_algorithms = [
            algorithm
            for algorithm in REQUIRED_HASH_ALGORITHMS
            if str(row[algorithm]).lower() == incoming_hashes[algorithm]
        ]
        for algorithm in matched_algorithms:
            record_identity_conflict(
                connection,
                file_id=existing_file_id,
                related_file_id=incoming_file_id,
                conflict_type="required_hash_overlap",
                algorithm=algorithm,
                existing_value=str(row[algorithm]),
                incoming_value=incoming_hashes[algorithm],
                incoming_size_bytes=incoming_size_bytes,
                incoming_hashes=incoming_hashes,
                notes=(
                    "Distinct required identity tuples share exact size and "
                    f"{algorithm}; stored as separate UFID records"
                ),
            )


def _metadata_entries(
    *,
    display_name: str | None,
    description: str | None,
    content_type: str | None,
    metadata: Mapping[str, str] | Sequence[Mapping[str, Any]] | None,
) -> Iterable[dict[str, str | None]]:
    if display_name:
        yield {
            "metadata_type": "text",
            "name": "filename",
            "value": display_name,
            "notes": None,
        }
    if description:
        yield {
            "metadata_type": "text",
            "name": "description",
            "value": description,
            "notes": None,
        }
    if content_type:
        yield {
            "metadata_type": "text",
            "name": "content_type",
            "value": content_type,
            "notes": None,
        }

    if metadata is None:
        return
    if isinstance(metadata, Mapping):
        for key, value in metadata.items():
            if value is None:
                continue
            yield {
                "metadata_type": "text",
                "name": str(key),
                "value": str(value),
                "notes": None,
            }
        return

    for item in metadata:
        value = item.get("value")
        if value is None:
            continue
        metadata_type = str(item.get("metadata_type") or item.get("type") or "text").lower()
        if metadata_type not in ALLOWED_METADATA_TYPES:
            allowed = ", ".join(ALLOWED_METADATA_TYPES)
            raise ValueError(f"metadata_type must be one of: {allowed}")
        name = str(item.get("name") or "").strip()
        if not name:
            raise ValueError("metadata name is required")
        yield {
            "metadata_type": metadata_type,
            "name": name,
            "value": str(value),
            "notes": None if item.get("notes") is None else str(item["notes"]),
        }


def _normalize_goldrush_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    hashes_payload = alert.get("hashes") or {}
    if not isinstance(hashes_payload, Mapping):
        raise ValueError("hashes must be an object")
    raw_hashes: dict[str, str | None] = {
        str(key): None if value is None else str(value)
        for key, value in hashes_payload.items()
    }
    for algorithm in SUPPORTED_HASH_ALGORITHMS:
        if algorithm in alert and alert[algorithm] is not None:
            raw_hashes[algorithm] = str(alert[algorithm])

    hashes = normalize_hashes(raw_hashes)
    if not hashes:
        raise ValueError("at least one supported hash is required")
    _validate_hash_values(hashes)

    normalized = {
        "name": _required_text(alert.get("name"), "name"),
        "description": _required_text(alert.get("description"), "description"),
        "size_bytes": _optional_size_bytes(alert.get("size_bytes")),
        "source_type": _optional_text(alert.get("source_type")),
        "source_name": _optional_text(alert.get("source_name")),
        "source_detail": _optional_text(alert.get("source_detail")),
    }
    for algorithm in SUPPORTED_HASH_ALGORITHMS:
        normalized[algorithm] = hashes.get(algorithm)
    normalized["fingerprint"] = _goldrush_fingerprint(normalized)
    return normalized


def _insert_goldrush_alert(
    connection: sqlite3.Connection,
    row: Mapping[str, Any],
) -> bool:
    values = [row[column] for column in GOLDRUSH_ALERT_COLUMNS]
    placeholders = ", ".join("?" for _ in GOLDRUSH_ALERT_COLUMNS)
    columns = ", ".join(GOLDRUSH_ALERT_COLUMNS)
    cursor = connection.execute(
        f"""
        INSERT OR IGNORE INTO ufid_goldrush_alert ({columns})
        VALUES ({placeholders})
        """,
        values,
    )
    return cursor.rowcount > 0


def _get_goldrush_alert_by_fingerprint(
    connection: sqlite3.Connection,
    fingerprint: str,
) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM ufid_goldrush_alert WHERE fingerprint = ?",
        (fingerprint,),
    ).fetchone()
    if row is None:
        return None
    return _goldrush_alert_row(row)


def _goldrush_alert_row(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result.pop("fingerprint", None)
    result["hashes"] = {
        algorithm: result.get(algorithm)
        for algorithm in SUPPORTED_HASH_ALGORITHMS
    }
    return result


def _goldrush_alert_source_row(row: Mapping[str, Any]) -> dict[str, Any]:
    values = dict(row)
    return {
        "source_key": values["source_key"],
        "label": values["label"],
        "source_type": values["source_type"],
        "source_name": values["source_name"],
        "alert_count": int(values["alert_count"]),
    }


def _goldrush_match_row(row: Mapping[str, Any]) -> dict[str, Any]:
    values = dict(row)
    alert_hashes = {
        algorithm: values.get(f"alert_{algorithm}")
        for algorithm in SUPPORTED_HASH_ALGORITHMS
    }
    file_hashes = {
        algorithm: values.get(f"file_{algorithm}")
        for algorithm in SUPPORTED_HASH_ALGORITHMS
    }
    internet_archive = _goldrush_match_internet_archive(values)
    matched_algorithms = [
        algorithm
        for algorithm in SUPPORTED_HASH_ALGORITHMS
        if values.get(f"matched_{algorithm}")
    ]
    return {
        "alert": {
            "id": values["alert_id"],
            "name": values["alert_name"],
            "description": values["alert_description"],
            "size_bytes": values["alert_size_bytes"],
            "hashes": alert_hashes,
            "source_type": values["alert_source_type"],
            "source_name": values["alert_source_name"],
            "source_detail": values["alert_source_detail"],
            "created_at": values["alert_created_at"],
        },
        "file": {
            "id": values["file_id"],
            "size_bytes": values["file_size_bytes"],
            "display_name": values["file_display_name"] or None,
            "content_type": values["file_content_type"],
            "hashes": file_hashes,
            "internet_archive": internet_archive,
        },
        "matched_algorithms": matched_algorithms,
        "size_matched": bool(values["size_matched"]),
    }


def _goldrush_match_internet_archive(values: Mapping[str, Any]) -> dict[str, Any] | None:
    if not values.get("ia_identifier") and not values.get("ia_item_url"):
        return None
    identifier = values.get("ia_identifier")
    item_url = values.get("ia_item_url")
    if not item_url and identifier:
        item_url = f"https://archive.org/details/{identifier}"
    return {
        "source_file_id": values.get("source_file_id"),
        "identifier": identifier,
        "item_url": item_url,
        "file_url": values.get("ia_file_url"),
        "file_name": values.get("ia_file_name"),
    }


def _goldrush_alert_filter(query: str | None) -> tuple[str, tuple[str, ...]]:
    if not query:
        return "", ()
    like = f"%{query}%"
    return (
        """
        WHERE CAST(a.id AS TEXT) LIKE ?
           OR CAST(a.size_bytes AS TEXT) LIKE ?
           OR a.name LIKE ?
           OR a.description LIKE ?
           OR a.crc32 LIKE ?
           OR a.md5 LIKE ?
           OR a.sha1 LIKE ?
           OR a.sha256 LIKE ?
           OR a.blake3 LIKE ?
           OR a.source_type LIKE ?
           OR a.source_name LIKE ?
           OR a.source_detail LIKE ?
        """,
        (like, like, like, like, like, like, like, like, like, like, like, like),
    )


def _goldrush_match_cte_sql(*, include_sources: bool = False) -> str:
    source_ctes = (
        """
        ,
        goldrush_match_ancestor(file_id, ancestor_file_id, depth) AS (
            SELECT file_id, file_id, 0
            FROM goldrush_match

            UNION ALL

            SELECT
                gma.file_id,
                am.parent_file_id,
                gma.depth + 1
            FROM goldrush_match_ancestor gma
            JOIN ufid_archive_member am
              ON am.child_file_id = gma.ancestor_file_id
            WHERE gma.depth < 128
        ),
        goldrush_match_ia_candidate AS (
            SELECT *
            FROM (
                SELECT
                    gma.file_id,
                    gma.ancestor_file_id AS source_file_id,
                    gma.depth,
                    (
                        SELECT fm.value
                        FROM ufid_file_meta fm
                        WHERE fm.file_id = gma.ancestor_file_id
                          AND fm.name = 'ia_identifier'
                        ORDER BY fm.added_at, fm.id
                        LIMIT 1
                    ) AS ia_identifier,
                    (
                        SELECT fm.value
                        FROM ufid_file_meta fm
                        WHERE fm.file_id = gma.ancestor_file_id
                          AND fm.name = 'ia_item_url'
                        ORDER BY fm.added_at, fm.id
                        LIMIT 1
                    ) AS ia_item_url,
                    (
                        SELECT fm.value
                        FROM ufid_file_meta fm
                        WHERE fm.file_id = gma.ancestor_file_id
                          AND fm.name = 'ia_file_url'
                        ORDER BY fm.added_at, fm.id
                        LIMIT 1
                    ) AS ia_file_url,
                    (
                        SELECT fm.value
                        FROM ufid_file_meta fm
                        WHERE fm.file_id = gma.ancestor_file_id
                          AND fm.name = 'ia_file_name'
                        ORDER BY fm.added_at, fm.id
                        LIMIT 1
                    ) AS ia_file_name
                FROM goldrush_match_ancestor gma
            ) c
            WHERE c.ia_identifier IS NOT NULL
               OR c.ia_item_url IS NOT NULL
        ),
        goldrush_match_ia_source AS (
            SELECT
                source_file_id,
                file_id,
                ia_identifier,
                ia_item_url,
                ia_file_url,
                ia_file_name
            FROM (
                SELECT
                    c.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY c.file_id
                        ORDER BY c.depth DESC, c.source_file_id ASC
                    ) AS source_rank
                FROM goldrush_match_ia_candidate c
            ) ranked
            WHERE source_rank = 1
        )
        """
        if include_sources
        else ""
    )
    return f"""
        WITH RECURSIVE goldrush_match_pair AS (
            SELECT a.id AS alert_id, f.id AS file_id, 'crc32' AS algorithm
            FROM ufid_goldrush_alert a
            JOIN ufid_file f ON f.crc32 = a.crc32
            WHERE a.crc32 IS NOT NULL
              AND (a.size_bytes IS NULL OR a.size_bytes = f.size_bytes)

            UNION ALL

            SELECT a.id AS alert_id, f.id AS file_id, 'md5' AS algorithm
            FROM ufid_goldrush_alert a
            JOIN ufid_file f ON f.md5 = a.md5
            WHERE a.md5 IS NOT NULL
              AND (a.size_bytes IS NULL OR a.size_bytes = f.size_bytes)

            UNION ALL

            SELECT a.id AS alert_id, f.id AS file_id, 'sha1' AS algorithm
            FROM ufid_goldrush_alert a
            JOIN ufid_file f ON f.sha1 = a.sha1
            WHERE a.sha1 IS NOT NULL
              AND (a.size_bytes IS NULL OR a.size_bytes = f.size_bytes)

            UNION ALL

            SELECT a.id AS alert_id, f.id AS file_id, 'sha256' AS algorithm
            FROM ufid_goldrush_alert a
            JOIN ufid_file f ON f.sha256 = a.sha256
            WHERE a.sha256 IS NOT NULL
              AND (a.size_bytes IS NULL OR a.size_bytes = f.size_bytes)

            UNION ALL

            SELECT a.id AS alert_id, f.id AS file_id, 'blake3' AS algorithm
            FROM ufid_goldrush_alert a
            JOIN ufid_file f ON f.blake3 = a.blake3
            WHERE a.blake3 IS NOT NULL
              AND (a.size_bytes IS NULL OR a.size_bytes = f.size_bytes)
        ),
        goldrush_match AS (
            SELECT
                alert_id,
                file_id,
                MAX(CASE WHEN algorithm = 'crc32' THEN 1 ELSE 0 END) AS matched_crc32,
                MAX(CASE WHEN algorithm = 'md5' THEN 1 ELSE 0 END) AS matched_md5,
                MAX(CASE WHEN algorithm = 'sha1' THEN 1 ELSE 0 END) AS matched_sha1,
                MAX(CASE WHEN algorithm = 'sha256' THEN 1 ELSE 0 END) AS matched_sha256,
                MAX(CASE WHEN algorithm = 'blake3' THEN 1 ELSE 0 END) AS matched_blake3
            FROM goldrush_match_pair
            GROUP BY alert_id, file_id
        )
        {source_ctes}
    """


def _goldrush_match_from_sql(*, include_sources: bool = False) -> str:
    source_join = (
        "LEFT JOIN goldrush_match_ia_source s ON s.file_id = f.id"
        if include_sources
        else ""
    )
    return f"""
        FROM goldrush_match m
        JOIN ufid_goldrush_alert a ON a.id = m.alert_id
        JOIN ufid_file f ON f.id = m.file_id
        {source_join}
        WHERE 1 = 1
    """


def _goldrush_match_filter(
    query: str | None,
    *,
    source_keys: Sequence[str] | None = None,
) -> tuple[str, tuple[str, ...]]:
    clauses: list[str] = []
    params: list[str] = []
    if query:
        like = f"%{query}%"
        clauses.append(
            """
              CAST(a.id AS TEXT) LIKE ?
           OR CAST(f.id AS TEXT) LIKE ?
           OR CAST(a.size_bytes AS TEXT) LIKE ?
           OR CAST(f.size_bytes AS TEXT) LIKE ?
           OR a.name LIKE ?
           OR a.description LIKE ?
           OR a.crc32 LIKE ?
           OR a.md5 LIKE ?
           OR a.sha1 LIKE ?
           OR a.sha256 LIKE ?
           OR a.blake3 LIKE ?
           OR a.source_type LIKE ?
           OR a.source_name LIKE ?
           OR a.source_detail LIKE ?
           OR f.crc32 LIKE ?
           OR f.md5 LIKE ?
           OR f.sha1 LIKE ?
           OR f.sha256 LIKE ?
           OR f.blake3 LIKE ?
           OR EXISTS (
                SELECT 1
                FROM ufid_file_meta fm
                WHERE fm.file_id = f.id
                  AND (
                    fm.name LIKE ?
                    OR fm.value LIKE ?
                    OR fm.notes LIKE ?
                  )
           )
            """
        )
        params.extend([like] * 22)

    normalized_source_keys = _normalize_goldrush_source_keys(source_keys)
    if normalized_source_keys:
        placeholders = ", ".join("?" for _ in normalized_source_keys)
        clauses.append(f"{_goldrush_alert_source_key_sql()} IN ({placeholders})")
        params.extend(normalized_source_keys)

    if not clauses:
        return "", ()
    sql = "\n".join(f"          AND ({clause}\n          )" for clause in clauses)
    return sql, tuple(params)


def _goldrush_alert_source_key_sql() -> str:
    return """
        CASE
            WHEN COALESCE(a.source_type, '') = ''
             AND COALESCE(a.source_name, '') = ''
            THEN 'manual'
            ELSE COALESCE(a.source_type, '') || '|' || COALESCE(a.source_name, '')
        END
    """


def _normalize_goldrush_source_keys(
    source_keys: Sequence[str] | None,
) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in source_keys or ():
        text = str(value).strip()
        if text and text not in normalized:
            normalized.append(text)
    return tuple(normalized)


def _required_text(value: Any, name: str) -> str:
    text = _optional_text(value)
    if text is None:
        raise ValueError(f"{name} is required")
    return text


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_size_bytes(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("size_bytes must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("size_bytes must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError("size_bytes must be a non-negative integer")
    return parsed


def _goldrush_fingerprint(row: Mapping[str, Any]) -> str:
    payload = {
        "name": row.get("name"),
        "description": row.get("description"),
        "size_bytes": row.get("size_bytes"),
        "hashes": {
            algorithm: row.get(algorithm)
            for algorithm in SUPPORTED_HASH_ALGORITHMS
        },
        "source_type": row.get("source_type"),
        "source_name": row.get("source_name"),
        "source_detail": row.get("source_detail"),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _file_list_sort(sort_by: str, sort_direction: str) -> tuple[str, str]:
    key = (sort_by or "id").strip().lower()
    if key not in FILE_LIST_SORT_COLUMNS:
        supported = ", ".join(sorted(FILE_LIST_SORT_COLUMNS))
        raise ValueError(f"sort must be one of: {supported}")

    direction = (sort_direction or "desc").strip().lower()
    if direction not in {"asc", "desc"}:
        raise ValueError("direction must be asc or desc")

    return FILE_LIST_SORT_COLUMNS[key], direction.upper()


def _file_list_filter(query: str | None) -> tuple[str, tuple[str, ...]]:
    if not query:
        return "", ()
    like = f"%{query}%"
    return (
        """
        WHERE CAST(f.id AS TEXT) LIKE ?
           OR CAST(f.size_bytes AS TEXT) LIKE ?
           OR f.crc32 LIKE ?
           OR f.md5 LIKE ?
           OR f.sha1 LIKE ?
           OR f.sha256 LIKE ?
           OR f.blake3 LIKE ?
           OR EXISTS (
                SELECT 1
                FROM ufid_file_meta fm
                WHERE fm.file_id = f.id
                  AND (
                    fm.metadata_type LIKE ?
                    OR fm.name LIKE ?
                    OR fm.value LIKE ?
                    OR fm.notes LIKE ?
                  )
           )
           OR EXISTS (
                SELECT 1
                FROM ufid_archive_member am
                WHERE am.parent_file_id = f.id
                  AND am.archive_path LIKE ?
           )
           OR EXISTS (
                SELECT 1
                FROM ufid_identity_conflict cf
                WHERE (cf.file_id = f.id OR cf.related_file_id = f.id)
                  AND (
                    cf.conflict_type LIKE ?
                    OR cf.algorithm LIKE ?
                    OR cf.existing_value LIKE ?
                    OR cf.incoming_value LIKE ?
                    OR cf.notes LIKE ?
                  )
           )
        """,
        (
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like,
        ),
    )


def _insert_metadata_if_new(
    connection: sqlite3.Connection,
    file_id: int,
    item: Mapping[str, str | None],
) -> bool:
    existing = connection.execute(
        """
        SELECT id
        FROM ufid_file_meta
        WHERE file_id = ?
          AND metadata_type = ?
          AND name = ?
          AND value = ?
          AND COALESCE(notes, '') = COALESCE(?, '')
        """,
        (
            file_id,
            item["metadata_type"],
            item["name"],
            item["value"],
            item["notes"],
        ),
    ).fetchone()
    if existing is not None:
        return False

    connection.execute(
        """
        INSERT INTO ufid_file_meta (
            file_id,
            metadata_type,
            name,
            value,
            notes
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            file_id,
            item["metadata_type"],
            item["name"],
            item["value"],
            item["notes"],
        ),
    )
    return True


def _derived_metadata_fields(metadata: Sequence[Mapping[str, Any]]) -> dict[str, str | None]:
    return {
        "display_name": _first_metadata_value(metadata, "filename"),
        "description": _first_metadata_value(metadata, "description"),
        "content_type": _first_metadata_value(metadata, "content_type")
        or _first_metadata_value(metadata, "filetype"),
    }


def _first_metadata_value(
    metadata: Sequence[Mapping[str, Any]],
    name: str,
) -> str | None:
    for item in metadata:
        if item["name"] == name:
            return str(item["value"])
    return None


def _hash_column(algorithm: str) -> str:
    normalized = algorithm.lower().replace("-", "")
    if normalized not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return normalized
