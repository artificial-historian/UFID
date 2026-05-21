from __future__ import annotations

import argparse
from contextlib import closing
import hmac
from http.cookies import SimpleCookie
import json
import logging
import sqlite3
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlparse

from ufid.auth import AuthenticatedUser, DEFAULT_SESSION_SECONDS, SESSION_COOKIE_NAME
from ufid.database import (
    IdentityConflict,
    add_archive_member,
    add_file_metadata,
    authenticate_user,
    connect,
    count_files,
    count_goldrush_alerts,
    count_goldrush_matches,
    create_goldrush_alert,
    create_session,
    create_user,
    find_files_by_hash,
    get_authenticated_user,
    get_file,
    import_goldrush_alerts,
    list_goldrush_alerts,
    list_goldrush_alert_sources,
    list_files,
    list_goldrush_matches,
    revoke_session,
    upsert_file_identity,
)
from ufid.goldrush import parse_logiqx_dat
from ufid.paths import default_sqlite_db_path, resolve_web_root


LOGGER = logging.getLogger(__name__)
MAX_JSON_BODY_BYTES = 64 * 1024 * 1024


class UFIDRequestHandler(SimpleHTTPRequestHandler):
    db_path: Path
    web_root: Path
    secure_cookies = False
    cors_origin: str | None = None
    local_api_token: str | None = None
    local_api_roles: Sequence[str] = ("reader", "contributor")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.web_root), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def end_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and self.cors_origin and origin == self.cors_origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self) -> None:
        try:
            self._dispatch_get()
        except Exception as exc:
            self._handle_unexpected_error(exc)

    def _dispatch_get(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/auth/session":
            self._handle_auth_session()
            return
        if parsed.path == "/api/v1/files/by-hash":
            if not self._require_role("reader"):
                return
            self._handle_find_by_hash(parsed.query)
            return
        if parsed.path == "/api/v1/files":
            if not self._require_role("reader"):
                return
            self._handle_list_files(parsed.query)
            return
        if parsed.path == "/api/v1/goldrush/alerts":
            if not self._require_role("reader"):
                return
            self._handle_list_goldrush_alerts(parsed.query)
            return
        if parsed.path == "/api/v1/goldrush/alert-sources":
            if not self._require_role("reader"):
                return
            self._handle_list_goldrush_alert_sources()
            return
        if parsed.path == "/api/v1/goldrush/matches":
            if not self._require_role("reader"):
                return
            self._handle_list_goldrush_matches(parsed.query)
            return
        if parsed.path.startswith("/api/v1/files/"):
            if not self._require_role("reader"):
                return
            self._handle_get_file(parsed.path)
            return
        if parsed.path == "/health":
            self._write_json({"ok": True})
            return
        super().do_GET()

    def do_POST(self) -> None:
        try:
            self._dispatch_post()
        except Exception as exc:
            self._handle_unexpected_error(exc)

    def _dispatch_post(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/auth/login":
            self._handle_auth_login()
            return
        if parsed.path == "/api/v1/auth/logout":
            self._handle_auth_logout()
            return
        if parsed.path == "/api/v1/auth/users":
            if not self._require_role("admin"):
                return
            self._handle_create_user()
            return
        if parsed.path == "/api/v1/files":
            if not self._require_role("contributor"):
                return
            self._handle_upsert_file()
            return
        if parsed.path == "/api/v1/goldrush/alerts":
            if not self._require_role("contributor"):
                return
            self._handle_create_goldrush_alert()
            return
        if parsed.path == "/api/v1/goldrush/import-dat":
            if not self._require_role("contributor"):
                return
            self._handle_import_goldrush_dat()
            return
        if (
            parsed.path.startswith("/api/v1/files/")
            and parsed.path.endswith("/metadata")
        ):
            if not self._require_role("contributor"):
                return
            self._handle_add_file_metadata(parsed.path)
            return
        if parsed.path == "/api/v1/archive-members":
            if not self._require_role("contributor"):
                return
            self._handle_add_archive_member()
            return
        self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_auth_login(self) -> None:
        try:
            payload = self._read_json()
            username = str(payload.get("username") or "")
            password = str(payload.get("password") or "")
            with self._connect() as connection:
                user = authenticate_user(
                    connection,
                    username=username,
                    password=password,
                )
                if user is None:
                    self._write_json(
                        {"error": "Invalid username or password"},
                        status=HTTPStatus.UNAUTHORIZED,
                    )
                    return
                token, session_user = create_session(
                    connection,
                    user_id=int(user["id"]),
                    user_agent=self.headers.get("User-Agent"),
                    ip_address=self.client_address[0],
                )
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self._write_json(
            {
                "authenticated": True,
                "token": token,
                "token_type": "Bearer",
                "expires_at": session_user.expires_at,
                "user": session_user.to_public_dict(),
            },
            headers=[
                (
                    "Set-Cookie",
                    self._session_cookie_header(token, DEFAULT_SESSION_SECONDS),
                )
            ],
        )

    def _handle_auth_session(self) -> None:
        user = self._current_user()
        if user is None:
            self._write_json({"authenticated": False})
            return
        self._write_json({"authenticated": True, "user": user.to_public_dict()})

    def _handle_auth_logout(self) -> None:
        token = self._session_token()
        with self._connect() as connection:
            revoked = revoke_session(connection, token)
        self._write_json(
            {"revoked": revoked},
            headers=[("Set-Cookie", self._expired_session_cookie_header())],
        )

    def _handle_create_user(self) -> None:
        try:
            payload = self._read_json()
            roles = payload.get("roles") or ["reader"]
            if not isinstance(roles, list):
                raise ValueError("roles must be a list")
            with self._connect() as connection:
                user = create_user(
                    connection,
                    username=str(payload.get("username") or ""),
                    password=str(payload.get("password") or ""),
                    display_name=payload.get("display_name"),
                    roles=[str(role) for role in roles],
                )
        except sqlite3.IntegrityError:
            self._write_json({"error": "username already exists"}, status=HTTPStatus.CONFLICT)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self._write_json({"user": _public_user_dict(user)}, status=HTTPStatus.CREATED)

    def _handle_find_by_hash(self, query: str) -> None:
        params = parse_qs(query)
        algorithm = _single_query_value(params, "algorithm")
        hash_value = _single_query_value(params, "value")
        try:
            size_bytes = _optional_int_query_value(params, "size")
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        if not algorithm or not hash_value:
            self._write_json(
                {"error": "algorithm and value are required"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        with self._connect() as connection:
            file_records = find_files_by_hash(
                connection,
                algorithm,
                hash_value,
                size_bytes=size_bytes,
            )
        if not file_records:
            self._write_json({"found": False})
            return
        self._write_json(
            {
                "found": True,
                "file": file_records[0],
                "files": file_records,
                "count": len(file_records),
            }
        )

    def _handle_list_files(self, query: str) -> None:
        params = parse_qs(query)
        try:
            limit = _int_query_value(params, "limit", default=50)
            offset = _int_query_value(params, "offset", default=0)
            limit = _bounded_list_limit(limit)
            sort_by = (_single_query_value(params, "sort") or "id").strip().lower()
            sort_direction = (_single_query_value(params, "direction") or "desc").strip().lower()
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        search = _single_query_value(params, "q")
        try:
            with self._connect() as connection:
                files = list_files(
                    connection,
                    limit=limit,
                    offset=offset,
                    query=search,
                    sort_by=sort_by,
                    sort_direction=sort_direction,
                )
                total_count = count_files(connection, query=search)
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        self._write_json(
            {
                "files": files,
                "limit": limit,
                "offset": offset,
                "count": len(files),
                "total_count": total_count,
                "sort": sort_by,
                "direction": sort_direction,
                "next_offset": offset + len(files) if offset + len(files) < total_count else None,
            }
        )

    def _handle_list_goldrush_alerts(self, query: str) -> None:
        params = parse_qs(query)
        try:
            limit = _bounded_list_limit(_int_query_value(params, "limit", default=200))
            offset = _int_query_value(params, "offset", default=0)
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        search = _single_query_value(params, "q")
        with self._connect() as connection:
            alerts = list_goldrush_alerts(
                connection,
                limit=limit,
                offset=offset,
                query=search,
            )
            total_count = count_goldrush_alerts(connection, query=search)
        self._write_json(
            {
                "alerts": alerts,
                "limit": limit,
                "offset": offset,
                "count": len(alerts),
                "total_count": total_count,
                "next_offset": offset + len(alerts) if offset + len(alerts) < total_count else None,
            }
        )

    def _handle_list_goldrush_alert_sources(self) -> None:
        with self._connect() as connection:
            sources = list_goldrush_alert_sources(connection)
        self._write_json({"sources": sources, "count": len(sources)})

    def _handle_list_goldrush_matches(self, query: str) -> None:
        params = parse_qs(query)
        try:
            limit = _bounded_list_limit(_int_query_value(params, "limit", default=200))
            offset = _int_query_value(params, "offset", default=0)
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        search = _single_query_value(params, "q")
        source_keys = tuple(
            value.strip()
            for value in params.get("source_key", [])
            if value.strip()
        )
        with self._connect() as connection:
            matches = list_goldrush_matches(
                connection,
                limit=limit,
                offset=offset,
                query=search,
                source_keys=source_keys,
            )
            total_count = count_goldrush_matches(
                connection,
                query=search,
                source_keys=source_keys,
            )
        self._write_json(
            {
                "matches": matches,
                "limit": limit,
                "offset": offset,
                "count": len(matches),
                "total_count": total_count,
                "next_offset": offset + len(matches) if offset + len(matches) < total_count else None,
            }
        )

    def _handle_get_file(self, path: str) -> None:
        raw_file_id = path.removeprefix("/api/v1/files/").strip("/")
        try:
            file_id = int(raw_file_id)
        except ValueError:
            self._write_json({"error": "Invalid UFID id"}, status=HTTPStatus.BAD_REQUEST)
            return

        with self._connect() as connection:
            file_record = get_file(connection, file_id)
        if file_record is None:
            self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self._write_json({"file": file_record})

    def _handle_upsert_file(self) -> None:
        try:
            payload = self._read_json()
            hashes = payload.get("hashes")
            if not isinstance(hashes, dict) or not hashes:
                raise ValueError("hashes object is required")
            metadata = payload.get("metadata") or {}
            if not isinstance(metadata, (dict, list)):
                raise ValueError("metadata must be an object or list")

            with self._connect() as connection:
                result = upsert_file_identity(
                    connection,
                    display_name=payload.get("display_name"),
                    size_bytes=_coerce_payload_size(payload.get("size_bytes")),
                    description=payload.get("description"),
                    content_type=payload.get("content_type"),
                    hashes={
                        str(key): None if value is None else str(value)
                        for key, value in hashes.items()
                    },
                    metadata=_coerce_metadata_payload(metadata),
                )
        except IdentityConflict as exc:
            payload: dict[str, Any] = {"error": str(exc)}
            if exc.file_id is not None:
                payload["file_id"] = exc.file_id
            if exc.conflict_type is not None:
                payload["conflict_type"] = exc.conflict_type
            self._write_json(payload, status=HTTPStatus.CONFLICT)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self._write_json(
            {
                "id": result.file_id,
                "created": result.created,
                "enriched": result.enriched,
            },
            status=HTTPStatus.CREATED if result.created else HTTPStatus.OK,
        )

    def _handle_create_goldrush_alert(self) -> None:
        try:
            payload = self._read_json()
            hashes = payload.get("hashes")
            if not isinstance(hashes, dict) or not hashes:
                raise ValueError("hashes object is required")
            with self._connect() as connection:
                result = create_goldrush_alert(
                    connection,
                    name=str(payload.get("name") or ""),
                    description=str(payload.get("description") or ""),
                    size_bytes=payload.get("size_bytes"),
                    hashes={
                        str(key): None if value is None else str(value)
                        for key, value in hashes.items()
                    },
                    source_type=payload.get("source_type"),
                    source_name=payload.get("source_name"),
                    source_detail=payload.get("source_detail"),
                )
        except sqlite3.IntegrityError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self._write_json(
            result,
            status=HTTPStatus.CREATED if result["created"] else HTTPStatus.OK,
        )

    def _handle_import_goldrush_dat(self) -> None:
        try:
            payload = self._read_json()
            dat_text = payload.get("text") or payload.get("content") or payload.get("dat")
            if not isinstance(dat_text, str) or not dat_text.strip():
                raise ValueError("text is required")
            filename = payload.get("filename") or payload.get("name")
            filename = None if filename is None else str(filename)
            parsed = parse_logiqx_dat(dat_text, filename=filename)
            with self._connect() as connection:
                result = import_goldrush_alerts(connection, parsed.alerts)
        except sqlite3.IntegrityError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        response = {
            "source_name": parsed.source_name,
            "parsed": len(parsed.alerts),
            **result,
        }
        status = HTTPStatus.CREATED if result["created"] else HTTPStatus.OK
        if result["valid"] == 0 and result["errors"]:
            status = HTTPStatus.BAD_REQUEST
        self._write_json(response, status=status)

    def _handle_add_file_metadata(self, path: str) -> None:
        raw_file_id = (
            path.removeprefix("/api/v1/files/")
            .removesuffix("/metadata")
            .strip("/")
        )
        try:
            file_id = _coerce_positive_id(raw_file_id, "file_id")
            payload = self._read_json()
            metadata = payload.get("metadata") or payload.get("items") or []
            if not isinstance(metadata, (dict, list)):
                raise ValueError("metadata must be an object or list")
            with self._connect() as connection:
                if get_file(connection, file_id) is None:
                    self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                enriched = add_file_metadata(
                    connection,
                    file_id=file_id,
                    metadata=_coerce_metadata_payload(metadata),
                )
        except sqlite3.IntegrityError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self._write_json({"enriched": enriched})

    def _handle_add_archive_member(self) -> None:
        try:
            payload = self._read_json()
            parent_file_id = _coerce_positive_id(
                payload.get("parent_file_id"),
                "parent_file_id",
            )
            child_value = payload.get("child_file_id")
            child_file_id = (
                None
                if child_value is None
                else _coerce_positive_id(child_value, "child_file_id")
            )
            archive_path = payload.get("archive_path")
            archive_path = None if archive_path is None else str(archive_path)
            with self._connect() as connection:
                created = add_archive_member(
                    connection,
                    parent_file_id=parent_file_id,
                    child_file_id=child_file_id,
                    archive_path=archive_path,
                )
        except sqlite3.IntegrityError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self._write_json(
            {"created": created},
            status=HTTPStatus.CREATED if created else HTTPStatus.OK,
        )

    def _read_json(self) -> dict[str, Any]:
        return _read_json_payload(self.headers, self.rfile)

    def _write_json(
        self,
        payload: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _handle_unexpected_error(self, exc: Exception) -> None:
        if _is_sqlite_busy_error(exc):
            LOGGER.warning("SQLite database busy while handling %s: %s", self.path, exc)
            try:
                self._write_json(
                    {"error": "SQLite database is busy; retry shortly"},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                    headers=[("Retry-After", "1")],
                )
            except Exception:
                raise exc
            return

        LOGGER.exception("Unhandled UFID server error while handling %s", self.path)
        try:
            self._write_json(
                {"error": "Internal server error"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        except Exception:
            raise exc

    def _require_role(self, role: str) -> bool:
        user = self._current_user()
        if user is None:
            self._write_json({"error": "Authentication required"}, status=HTTPStatus.UNAUTHORIZED)
            return False
        if not _user_has_role(user.roles, role):
            self._write_json({"error": "Insufficient role"}, status=HTTPStatus.FORBIDDEN)
            return False
        return True

    def _current_user(self):
        token = self._session_token()
        if token is None:
            return None
        local_token = self.local_api_token
        if local_token and hmac.compare_digest(token, local_token):
            return AuthenticatedUser(
                id=0,
                username="local-automation",
                display_name="Local Automation",
                roles=tuple(self.local_api_roles),
            )
        with self._connect() as connection:
            return get_authenticated_user(connection, token)

    def _connect(self):
        return closing(connect(self.db_path))

    def _session_token(self) -> str | None:
        authorization = self.headers.get("Authorization") or ""
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            return token.strip()

        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(SESSION_COOKIE_NAME)
        if morsel is None or not morsel.value:
            return None
        return morsel.value

    def _session_cookie_header(self, token: str, max_age: int) -> str:
        parts = [
            f"{SESSION_COOKIE_NAME}={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={max_age}",
        ]
        if self.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)

    def _expired_session_cookie_header(self) -> str:
        parts = [
            f"{SESSION_COOKIE_NAME}=",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=0",
        ]
        if self.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)


def _single_query_value(params: dict[str, list[str]], key: str) -> str | None:
    values = params.get(key)
    if not values:
        return None
    return values[0]


def _int_query_value(
    params: dict[str, list[str]],
    key: str,
    *,
    default: int,
) -> int:
    value = _single_query_value(params, key)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{key} cannot be negative")
    return parsed


def _bounded_list_limit(limit: int) -> int:
    return min(max(limit, 1), 200)


def _optional_int_query_value(
    params: dict[str, list[str]],
    key: str,
) -> int | None:
    value = _single_query_value(params, key)
    if value is None or value == "":
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{key} cannot be negative")
    return parsed


def _coerce_payload_size(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("size_bytes must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("size_bytes must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError("size_bytes must be a non-negative integer")
    return parsed


def _coerce_positive_id(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


def _coerce_metadata_payload(metadata: Any) -> dict[str, str] | list[dict[str, Any]]:
    if isinstance(metadata, dict):
        return {str(key): str(value) for key, value in metadata.items()}
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(metadata):
        if not isinstance(item, dict):
            raise ValueError(f"metadata item {index} must be an object")
        rows.append(dict(item))
    return rows


def _read_json_payload(headers: Mapping[str, Any], stream: Any) -> dict[str, Any]:
    raw_length = headers.get("Content-Length", "0")
    try:
        length = int(raw_length or "0")
    except (TypeError, ValueError) as exc:
        raise ValueError("Content-Length must be an integer") from exc
    if length <= 0:
        raise ValueError("JSON request body is required")
    if length > MAX_JSON_BODY_BYTES:
        raise ValueError(
            f"JSON request body is too large; limit is {MAX_JSON_BODY_BYTES} bytes"
        )

    raw = stream.read(length)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("JSON request body must be UTF-8") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON request body: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON object is required")
    return payload


def _user_has_role(user_roles: Sequence[str], required: str) -> bool:
    grants = {
        "reader": {"reader", "contributor", "curator", "admin"},
        "contributor": {"contributor", "curator", "admin"},
        "curator": {"curator", "admin"},
        "admin": {"admin"},
    }
    return bool(set(user_roles) & grants[required])


def _is_sqlite_busy_error(exc: Exception) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).lower()
    return (
        "database is locked" in message
        or "database is busy" in message
        or "database table is locked" in message
    )


def _public_user_dict(user: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name"),
        "roles": list(user.get("roles") or []),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-server",
        description="Run a local UFID reference API and web interface.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=str(default_sqlite_db_path()))
    parser.add_argument(
        "--web-root",
        help=(
            "Static web UI root. Defaults to ./web in a source checkout or the "
            "packaged UFID web assets when installed."
        ),
    )
    parser.add_argument(
        "--secure-cookies",
        action="store_true",
        help="Mark auth cookies Secure. Use when serving through HTTPS.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db).resolve()
    try:
        web_root = resolve_web_root(args.web_root)
    except FileNotFoundError as exc:
        parser.exit(2, f"ufid-server: {exc}\n")

    connect(db_path).close()

    handler_class = type(
        "ConfiguredUFIDRequestHandler",
        (UFIDRequestHandler,),
        {
            "db_path": db_path,
            "web_root": web_root,
            "secure_cookies": bool(args.secure_cookies),
        },
    )
    server = ThreadingHTTPServer((args.host, args.port), handler_class)
    print(f"UFID server listening on http://{args.host}:{args.port}")
    print(f"SQLite database: {db_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UFID server")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
