from __future__ import annotations

from datetime import date, datetime
import logging
import os
from typing import Any, Iterable, Mapping, Sequence

from ufid.database import (
    GOLDRUSH_ALERT_COLUMNS,
    IDENTITY_CONFLICT_TYPES,
    OPTIONAL_HASH_ALGORITHMS,
    REQUIRED_HASH_ALGORITHMS,
    SUPPORTED_HASH_ALGORITHMS,
    IdentityConflict,
    UpsertResult,
    _derived_metadata_fields,
    _goldrush_alert_row,
    _goldrush_match_row,
    _hash_column,
    _metadata_entries,
    _normalize_goldrush_alert,
    _normalize_roles,
    _normalize_username,
    _validate_required_identity,
    normalize_hashes,
)
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
POSTGRES_FILE_LIST_SORT_COLUMNS = {
    "id": "f.id",
    "name": (
        "LOWER(COALESCE((SELECT fm.value FROM ufid_file_meta fm "
        "WHERE fm.file_id = f.id AND fm.name = 'filename' "
        "ORDER BY fm.added_at, fm.id LIMIT 1), ''))"
    ),
    "size": "f.size_bytes",
    "crc32": "f.crc32",
    "md5": "f.md5",
    "sha1": "f.sha1",
    "sha256": "COALESCE(f.sha256, '')",
    "blake3": "COALESCE(f.blake3, '')",
}


def connect(database_url: str | None = None):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL support requires psycopg. Install with: "
            "python -m pip install -e '.[postgres]'"
        ) from exc

    dsn = database_url or os.environ.get("UFID_DATABASE_URL")
    if not dsn:
        raise RuntimeError("UFID_DATABASE_URL is required for PostgreSQL mode")
    return psycopg.connect(dsn, row_factory=dict_row)


def create_user(
    connection,
    *,
    username: str,
    password: str,
    roles: Sequence[str] = ("reader",),
    display_name: str | None = None,
) -> dict[str, Any]:
    normalized_username = _normalize_username(username)
    normalized_roles = _normalize_roles(roles)
    password_hash = hash_password(password)
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ufid_user_account (username, password_hash, display_name)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (normalized_username, password_hash, display_name),
            )
            user_id = int(cursor.fetchone()["id"])
        _set_user_roles(connection, user_id=user_id, roles=normalized_roles)
    user = get_user_by_username(connection, normalized_username)
    assert user is not None
    return user


def authenticate_user(
    connection,
    *,
    username: str,
    password: str,
) -> dict[str, Any] | None:
    user = get_user_by_username(connection, username)
    if user is None or user.get("disabled_at"):
        return None
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT password_hash FROM ufid_user_account WHERE id = %s",
            (user["id"],),
        )
        row = cursor.fetchone()
    if row is None or not verify_password(password, str(row["password_hash"])):
        return None
    return user


def create_session(
    connection,
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
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
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
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, token_hash, now, expires_at, now, user_agent, ip_address),
            )
            session_id = int(cursor.fetchone()["id"])
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


def get_authenticated_user(connection, token: str | None) -> AuthenticatedUser | None:
    if not token:
        return None
    token_hash = hash_session_token(token)
    with connection.cursor() as cursor:
        cursor.execute(
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
            WHERE s.token_hash = %s
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
    if row is None or row["revoked_at"] or row["disabled_at"]:
        return None
    if parse_timestamp(row["expires_at"]) <= utc_now():
        return None

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE ufid_session SET last_seen_at = %s WHERE id = %s",
                (utc_now_iso(), row["session_id"]),
            )
    return AuthenticatedUser(
        id=int(row["user_id"]),
        username=str(row["username"]),
        display_name=row["display_name"],
        roles=tuple(get_user_roles(connection, int(row["user_id"]))),
        session_id=int(row["session_id"]),
        expires_at=_json_value(row["expires_at"]),
    )


def revoke_session(connection, token: str | None) -> bool:
    if not token:
        return False
    token_hash = hash_session_token(token)
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ufid_session
                SET revoked_at = %s
                WHERE token_hash = %s
                  AND revoked_at IS NULL
                """,
                (utc_now_iso(), token_hash),
            )
            return cursor.rowcount > 0


def get_user_by_username(connection, username: str) -> dict[str, Any] | None:
    normalized_username = _normalize_username(username)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, username, display_name, created_at, disabled_at
            FROM ufid_user_account
            WHERE lower(username) = lower(%s)
            """,
            (normalized_username,),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    user = _row_to_dict(row)
    user["roles"] = get_user_roles(connection, int(row["id"]))
    return user


def get_user_roles(connection, user_id: int) -> list[str]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT r.name
            FROM ufid_user_role ur
            JOIN ufid_role r ON r.id = ur.role_id
            WHERE ur.user_id = %s
            ORDER BY r.name
            """,
            (user_id,),
        )
        return [str(row["name"]) for row in cursor.fetchall()]


def find_files_by_hash(
    connection,
    algorithm: str,
    hash_value: str,
    size_bytes: int | None = None,
) -> list[dict[str, Any]]:
    column = _hash_column(algorithm)
    params: list[Any] = [hash_value]
    size_filter = ""
    if size_bytes is not None:
        size_filter = "AND size_bytes = %s"
        params.append(size_bytes)

    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT id
            FROM ufid_file
            WHERE {column} IS NOT NULL
              AND lower({column}) = lower(%s)
              {size_filter}
            ORDER BY id DESC
            """,
            params,
        )
        rows = cursor.fetchall()
    return [
        record
        for row in rows
        if (record := get_file(connection, int(row["id"]))) is not None
    ]


def get_file(connection, file_id: int) -> dict[str, Any] | None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM ufid_file WHERE id = %s", (file_id,))
        row = cursor.fetchone()
        if row is None:
            return None

        cursor.execute(
            """
            SELECT id, file_id, metadata_type, name, value, notes, added_at
            FROM ufid_file_meta
            WHERE file_id = %s
            ORDER BY added_at, id
            """,
            (file_id,),
        )
        metadata_rows = cursor.fetchall()

    result = _row_to_dict(row)
    metadata = [_row_to_dict(item) for item in metadata_rows]
    result["hashes"] = {
        algorithm: result.get(algorithm)
        for algorithm in SUPPORTED_HASH_ALGORITHMS
    }
    result["metadata"] = metadata
    result["archive_members"] = list_archive_members(connection, file_id)
    result["identity_conflicts"] = list_identity_conflicts(connection, file_id)
    result.update(_derived_metadata_fields(metadata))
    return result


def list_archive_members(connection, parent_file_id: int) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, parent_file_id, child_file_id, archive_path
            FROM ufid_archive_member
            WHERE parent_file_id = %s
            ORDER BY archive_path, id
            """,
            (parent_file_id,),
        )
        return [_row_to_dict(row) for row in cursor.fetchall()]


def list_identity_conflicts(connection, file_id: int) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
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
            WHERE file_id = %s
               OR related_file_id = %s
            ORDER BY logged_at, id
            """,
            (file_id, file_id),
        )
        return [_row_to_dict(row) for row in cursor.fetchall()]


def list_files(
    connection,
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
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT f.id
            FROM ufid_file f
            {where_sql}
            ORDER BY {sort_sql} {direction_sql}{tie_breaker}
            LIMIT %s OFFSET %s
            """,
            (*params, bounded_limit, bounded_offset),
        )
        rows = cursor.fetchall()
    return [
        record
        for row in rows
        if (record := get_file(connection, int(row["id"]))) is not None
    ]


def count_files(
    connection,
    *,
    query: str | None = None,
) -> int:
    where_sql, params = _file_list_filter(query)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM ufid_file f
            {where_sql}
            """,
            params,
        )
        row = cursor.fetchone()
    return int(row["total"] if row is not None else 0)


def upsert_file_identity(
    connection,
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

    with connection.transaction():
        existing = _find_identity_row(connection, size_bytes, normalized_hashes)
        if existing is None:
            required_overlaps = _find_required_hash_overlaps(
                connection,
                size_bytes,
                normalized_hashes,
            )
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO ufid_file (
                        size_bytes,
                        crc32,
                        md5,
                        sha1,
                        sha256,
                        blake3
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
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
                file_id = int(cursor.fetchone()["id"])
            created = True
            _record_required_hash_overlaps(
                connection,
                incoming_file_id=file_id,
                incoming_size_bytes=size_bytes,
                incoming_hashes=normalized_hashes,
                overlaps=required_overlaps,
            )
            metadata_entries = list(
                _metadata_entries(
                    display_name=display_name,
                    description=description,
                    content_type=content_type,
                    metadata=metadata,
                )
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
                metadata_entries = []
            else:
                metadata_entries = list(
                    _metadata_entries(
                        display_name=display_name,
                        description=description,
                        content_type=content_type,
                        metadata=metadata,
                    )
                )

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
                assignments = ", ".join(f"{key} = %s" for key in updates)
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"UPDATE ufid_file SET {assignments} WHERE id = %s",
                        [*updates.values(), file_id],
                    )
                enriched = True

        for item in metadata_entries:
            if _insert_metadata_if_new(connection, file_id, item):
                enriched = not created or enriched

    if deferred_conflict is not None:
        raise deferred_conflict

    return UpsertResult(file_id=file_id, created=created, enriched=enriched)


def add_archive_member(
    connection,
    *,
    parent_file_id: int,
    child_file_id: int | None,
    archive_path: str | None,
) -> bool:
    if child_file_id is None and not archive_path:
        raise ValueError("archive_path is required when child_file_id is NULL")

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ufid_archive_member (
                    parent_file_id,
                    child_file_id,
                    archive_path
                )
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING id
                """,
                (parent_file_id, child_file_id, archive_path),
            )
            return cursor.fetchone() is not None


def add_file_metadata(
    connection,
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
    with connection.transaction():
        for item in metadata_entries:
            if _insert_metadata_if_new(connection, file_id, item):
                enriched = True
    return enriched


def create_goldrush_alert(
    connection,
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
    with connection.transaction():
        created = _insert_goldrush_alert(connection, normalized)
    alert = _get_goldrush_alert_by_fingerprint(connection, normalized["fingerprint"])
    assert alert is not None
    return {"alert": alert, "created": created}


def import_goldrush_alerts(
    connection,
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
    with connection.transaction():
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
    connection,
    *,
    limit: int = 200,
    offset: int = 0,
    query: str | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = min(max(limit, 1), 200)
    bounded_offset = max(offset, 0)
    where_sql, params = _goldrush_alert_filter(query)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT *
            FROM ufid_goldrush_alert a
            {where_sql}
            ORDER BY a.id DESC
            LIMIT %s OFFSET %s
            """,
            (*params, bounded_limit, bounded_offset),
        )
        return [_goldrush_alert_row(row) for row in cursor.fetchall()]


def count_goldrush_alerts(
    connection,
    *,
    query: str | None = None,
) -> int:
    where_sql, params = _goldrush_alert_filter(query)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM ufid_goldrush_alert a
            {where_sql}
            """,
            params,
        )
        row = cursor.fetchone()
    return int(row["total"] if row is not None else 0)


def list_goldrush_matches(
    connection,
    *,
    limit: int = 200,
    offset: int = 0,
    query: str | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = min(max(limit, 1), 200)
    bounded_offset = max(offset, 0)
    filter_sql, params = _goldrush_match_filter(query)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
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
                (a.crc32 IS NOT NULL AND a.crc32 = f.crc32) AS matched_crc32,
                (a.md5 IS NOT NULL AND a.md5 = f.md5) AS matched_md5,
                (a.sha1 IS NOT NULL AND a.sha1 = f.sha1) AS matched_sha1,
                (a.sha256 IS NOT NULL AND a.sha256 = f.sha256) AS matched_sha256,
                (a.blake3 IS NOT NULL AND a.blake3 = f.blake3) AS matched_blake3,
                (a.size_bytes IS NOT NULL AND a.size_bytes = f.size_bytes) AS size_matched
            {_goldrush_match_from_sql()}
            {filter_sql}
            ORDER BY a.id DESC, f.id DESC
            LIMIT %s OFFSET %s
            """,
            (*params, bounded_limit, bounded_offset),
        )
        return [_goldrush_match_row(row) for row in cursor.fetchall()]


def count_goldrush_matches(
    connection,
    *,
    query: str | None = None,
) -> int:
    filter_sql, params = _goldrush_match_filter(query)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            {_goldrush_match_from_sql()}
            {filter_sql}
            """,
            params,
        )
        row = cursor.fetchone()
    return int(row["total"] if row is not None else 0)


def record_identity_conflict(
    connection,
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
    with connection.cursor() as cursor:
        cursor.execute(
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
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING id
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
        created = cursor.fetchone() is not None
    if created:
        LOGGER.warning(
            "Recorded UFID identity conflict: type=%s file_id=%s related_file_id=%s algorithm=%s",
            conflict_type,
            file_id,
            related_file_id,
            normalized_algorithm,
        )
    return created


def _find_identity_row(
    connection,
    size_bytes: int,
    hashes: Mapping[str, str],
) -> dict[str, Any] | None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT *
            FROM ufid_file
            WHERE size_bytes = %s
              AND lower(crc32) = lower(%s)
              AND lower(md5) = lower(%s)
              AND lower(sha1) = lower(%s)
            """,
            (size_bytes, hashes["crc32"], hashes["md5"], hashes["sha1"]),
        )
        return cursor.fetchone()


def _find_required_hash_overlaps(
    connection,
    size_bytes: int,
    hashes: Mapping[str, str],
) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, size_bytes, crc32, md5, sha1
            FROM ufid_file
            WHERE size_bytes = %s
              AND (
                  lower(crc32) = lower(%s)
               OR lower(md5) = lower(%s)
               OR lower(sha1) = lower(%s)
              )
              AND NOT (
                  lower(crc32) = lower(%s)
              AND lower(md5) = lower(%s)
              AND lower(sha1) = lower(%s)
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
        )
        return list(cursor.fetchall())


def _record_required_hash_overlaps(
    connection,
    *,
    incoming_file_id: int,
    incoming_size_bytes: int,
    incoming_hashes: Mapping[str, str],
    overlaps: Sequence[Mapping[str, Any]],
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


def _insert_metadata_if_new(
    connection,
    file_id: int,
    item: Mapping[str, str | None],
) -> bool:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id
            FROM ufid_file_meta
            WHERE file_id = %s
              AND metadata_type = %s
              AND name = %s
              AND value = %s
              AND COALESCE(notes, '') = COALESCE(%s, '')
            """,
            (
                file_id,
                item["metadata_type"],
                item["name"],
                item["value"],
                item["notes"],
            ),
        )
        if cursor.fetchone() is not None:
            return False

        cursor.execute(
            """
            INSERT INTO ufid_file_meta (
                file_id,
                metadata_type,
                name,
                value,
                notes
            )
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING id
            """,
            (
                file_id,
                item["metadata_type"],
                item["name"],
                item["value"],
                item["notes"],
            ),
        )
        return cursor.fetchone() is not None


def _file_list_sort(sort_by: str, sort_direction: str) -> tuple[str, str]:
    key = (sort_by or "id").strip().lower()
    if key not in POSTGRES_FILE_LIST_SORT_COLUMNS:
        supported = ", ".join(sorted(POSTGRES_FILE_LIST_SORT_COLUMNS))
        raise ValueError(f"sort must be one of: {supported}")

    direction = (sort_direction or "desc").strip().lower()
    if direction not in {"asc", "desc"}:
        raise ValueError("direction must be asc or desc")

    return POSTGRES_FILE_LIST_SORT_COLUMNS[key], direction.upper()


def _file_list_filter(query: str | None) -> tuple[str, tuple[str, ...]]:
    if not query:
        return "", ()
    like = f"%{query}%"
    return (
        """
        WHERE CAST(f.id AS TEXT) ILIKE %s
           OR CAST(f.size_bytes AS TEXT) ILIKE %s
           OR f.crc32 ILIKE %s
           OR f.md5 ILIKE %s
           OR f.sha1 ILIKE %s
           OR f.sha256 ILIKE %s
           OR f.blake3 ILIKE %s
           OR EXISTS (
                SELECT 1
                FROM ufid_file_meta fm
                WHERE fm.file_id = f.id
                  AND (
                    CAST(fm.metadata_type AS TEXT) ILIKE %s
                    OR fm.name ILIKE %s
                    OR fm.value ILIKE %s
                    OR fm.notes ILIKE %s
                  )
           )
           OR EXISTS (
                SELECT 1
                FROM ufid_archive_member am
                WHERE am.parent_file_id = f.id
                  AND am.archive_path ILIKE %s
           )
           OR EXISTS (
                SELECT 1
                FROM ufid_identity_conflict cf
                WHERE (cf.file_id = f.id OR cf.related_file_id = f.id)
                  AND (
                    CAST(cf.conflict_type AS TEXT) ILIKE %s
                    OR cf.algorithm ILIKE %s
                    OR cf.existing_value ILIKE %s
                    OR cf.incoming_value ILIKE %s
                    OR cf.notes ILIKE %s
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


def _insert_goldrush_alert(connection, row: Mapping[str, Any]) -> bool:
    values = [row[column] for column in GOLDRUSH_ALERT_COLUMNS]
    placeholders = ", ".join("%s" for _ in GOLDRUSH_ALERT_COLUMNS)
    columns = ", ".join(GOLDRUSH_ALERT_COLUMNS)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            INSERT INTO ufid_goldrush_alert ({columns})
            VALUES ({placeholders})
            ON CONFLICT (fingerprint) DO NOTHING
            RETURNING id
            """,
            values,
        )
        return cursor.fetchone() is not None


def _get_goldrush_alert_by_fingerprint(
    connection,
    fingerprint: str,
) -> dict[str, Any] | None:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM ufid_goldrush_alert WHERE fingerprint = %s",
            (fingerprint,),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    return _goldrush_alert_row(row)


def _goldrush_alert_filter(query: str | None) -> tuple[str, tuple[str, ...]]:
    if not query:
        return "", ()
    like = f"%{query}%"
    return (
        """
        WHERE CAST(a.id AS TEXT) ILIKE %s
           OR CAST(a.size_bytes AS TEXT) ILIKE %s
           OR a.name ILIKE %s
           OR a.description ILIKE %s
           OR a.crc32 ILIKE %s
           OR a.md5 ILIKE %s
           OR a.sha1 ILIKE %s
           OR a.sha256 ILIKE %s
           OR a.blake3 ILIKE %s
           OR a.source_type ILIKE %s
           OR a.source_name ILIKE %s
           OR a.source_detail ILIKE %s
        """,
        (like, like, like, like, like, like, like, like, like, like, like, like),
    )


def _goldrush_match_from_sql() -> str:
    return """
        FROM ufid_goldrush_alert a
        JOIN ufid_file f
          ON (
              (a.crc32 IS NOT NULL AND a.crc32 = f.crc32)
           OR (a.md5 IS NOT NULL AND a.md5 = f.md5)
           OR (a.sha1 IS NOT NULL AND a.sha1 = f.sha1)
           OR (a.sha256 IS NOT NULL AND a.sha256 = f.sha256)
           OR (a.blake3 IS NOT NULL AND a.blake3 = f.blake3)
          )
        WHERE (a.size_bytes IS NULL OR a.size_bytes = f.size_bytes)
    """


def _goldrush_match_filter(query: str | None) -> tuple[str, tuple[str, ...]]:
    if not query:
        return "", ()
    like = f"%{query}%"
    return (
        """
          AND (
              CAST(a.id AS TEXT) ILIKE %s
           OR CAST(f.id AS TEXT) ILIKE %s
           OR CAST(a.size_bytes AS TEXT) ILIKE %s
           OR CAST(f.size_bytes AS TEXT) ILIKE %s
           OR a.name ILIKE %s
           OR a.description ILIKE %s
           OR a.crc32 ILIKE %s
           OR a.md5 ILIKE %s
           OR a.sha1 ILIKE %s
           OR a.sha256 ILIKE %s
           OR a.blake3 ILIKE %s
           OR a.source_type ILIKE %s
           OR a.source_name ILIKE %s
           OR a.source_detail ILIKE %s
           OR f.crc32 ILIKE %s
           OR f.md5 ILIKE %s
           OR f.sha1 ILIKE %s
           OR f.sha256 ILIKE %s
           OR f.blake3 ILIKE %s
           OR EXISTS (
                SELECT 1
                FROM ufid_file_meta fm
                WHERE fm.file_id = f.id
                  AND (
                    fm.name ILIKE %s
                    OR fm.value ILIKE %s
                    OR fm.notes ILIKE %s
                  )
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
            like,
            like,
            like,
            like,
            like,
        ),
    )


def _set_user_roles(
    connection,
    *,
    user_id: int,
    roles: Sequence[str],
) -> None:
    with connection.cursor() as cursor:
        for role in roles:
            cursor.execute("SELECT id FROM ufid_role WHERE name = %s", (role,))
            row = cursor.fetchone()
            if row is None:
                raise ValueError(f"unknown role: {role}")
            cursor.execute(
                """
                INSERT INTO ufid_user_role (user_id, role_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
                """,
                (user_id, int(row["id"])),
            )


def _row_to_dict(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _json_value(value) for key, value in dict(row).items()}


def _json_value(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value
