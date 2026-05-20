from __future__ import annotations

import argparse
from http.cookies import SimpleCookie
import json
import logging
import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ufid import postgres_database as database
from ufid.auth import DEFAULT_SESSION_SECONDS, SESSION_COOKIE_NAME
from ufid.database import IdentityConflict
from ufid.paths import resolve_web_root
from ufid.server import (
    _coerce_metadata_payload,
    _coerce_payload_size,
    _coerce_positive_id,
    _int_query_value,
    _optional_int_query_value,
    _public_user_dict,
    _read_json_payload,
    _single_query_value,
    _user_has_role,
)


LOGGER = logging.getLogger(__name__)


class UFIDPostgresRequestHandler(SimpleHTTPRequestHandler):
    database_url: str
    web_root: Path
    secure_cookies = True
    cors_origin: str | None = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.web_root), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.address_string(), format % args)

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
            with database.connect(self.database_url) as connection:
                user = database.authenticate_user(
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
                token, session_user = database.create_session(
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
        with database.connect(self.database_url) as connection:
            revoked = database.revoke_session(connection, token)
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
            with database.connect(self.database_url) as connection:
                user = database.create_user(
                    connection,
                    username=str(payload.get("username") or ""),
                    password=str(payload.get("password") or ""),
                    display_name=payload.get("display_name"),
                    roles=[str(role) for role in roles],
                )
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            status, message = _postgres_constraint_response(exc)
            if status is not None:
                if status == HTTPStatus.CONFLICT and message == "record already exists":
                    message = "username already exists"
                self._write_json({"error": message}, status=status)
                return
            raise

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

        with database.connect(self.database_url) as connection:
            file_records = database.find_files_by_hash(
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
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        search = _single_query_value(params, "q")
        with database.connect(self.database_url) as connection:
            files = database.list_files(
                connection,
                limit=limit,
                offset=offset,
                query=search,
            )
        self._write_json(
            {
                "files": files,
                "limit": limit,
                "offset": offset,
                "count": len(files),
                "next_offset": offset + len(files) if len(files) == limit else None,
            }
        )

    def _handle_get_file(self, path: str) -> None:
        raw_file_id = path.removeprefix("/api/v1/files/").strip("/")
        try:
            file_id = int(raw_file_id)
        except ValueError:
            self._write_json({"error": "Invalid UFID id"}, status=HTTPStatus.BAD_REQUEST)
            return

        with database.connect(self.database_url) as connection:
            file_record = database.get_file(connection, file_id)
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

            with database.connect(self.database_url) as connection:
                result = database.upsert_file_identity(
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
            response: dict[str, Any] = {"error": str(exc)}
            if exc.file_id is not None:
                response["file_id"] = exc.file_id
            if exc.conflict_type is not None:
                response["conflict_type"] = exc.conflict_type
            self._write_json(response, status=HTTPStatus.CONFLICT)
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
            with database.connect(self.database_url) as connection:
                if database.get_file(connection, file_id) is None:
                    self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                enriched = database.add_file_metadata(
                    connection,
                    file_id=file_id,
                    metadata=_coerce_metadata_payload(metadata),
                )
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            status, message = _postgres_constraint_response(exc)
            if status is not None:
                self._write_json({"error": message}, status=status)
                return
            raise

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
            with database.connect(self.database_url) as connection:
                created = database.add_archive_member(
                    connection,
                    parent_file_id=parent_file_id,
                    child_file_id=child_file_id,
                    archive_path=archive_path,
                )
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            status, message = _postgres_constraint_response(exc)
            if status is not None:
                self._write_json({"error": message}, status=status)
                return
            raise

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
        LOGGER.exception("Unhandled UFID PostgreSQL server error while handling %s", self.path)
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
        with database.connect(self.database_url) as connection:
            return database.get_authenticated_user(connection, token)

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


def _postgres_sqlstate(exc: Exception) -> str:
    return str(getattr(exc, "sqlstate", "") or "")


def _postgres_constraint_response(exc: Exception) -> tuple[HTTPStatus | None, str]:
    sqlstate = _postgres_sqlstate(exc)
    if sqlstate == "23503":
        return HTTPStatus.CONFLICT, "referenced UFID record does not exist"
    if sqlstate == "23505":
        return HTTPStatus.CONFLICT, "record already exists"
    if sqlstate == "23514":
        return HTTPStatus.BAD_REQUEST, "database constraint rejected the request"

    message = str(exc).lower()
    if "foreign key" in message:
        return HTTPStatus.CONFLICT, "referenced UFID record does not exist"
    if "duplicate key" in message or "unique" in message:
        return HTTPStatus.CONFLICT, "record already exists"
    if "check constraint" in message:
        return HTTPStatus.BAD_REQUEST, "database constraint rejected the request"
    return None, ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-pg-server",
        description="Run a UFID HTTP API backed by PostgreSQL.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("UFID_DATABASE_URL"),
        help="PostgreSQL DSN. Defaults to UFID_DATABASE_URL.",
    )
    parser.add_argument(
        "--web-root",
        help=(
            "Static web UI root. Defaults to ./web in a source checkout or the "
            "packaged UFID web assets when installed."
        ),
    )
    parser.add_argument(
        "--insecure-cookies",
        action="store_true",
        help="Do not mark auth cookies Secure. Only use for local HTTP testing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.database_url:
        parser.exit(2, "ufid-pg-server: --database-url or UFID_DATABASE_URL is required\n")

    try:
        web_root = resolve_web_root(args.web_root)
    except FileNotFoundError as exc:
        parser.exit(2, f"ufid-pg-server: {exc}\n")

    with database.connect(args.database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

    handler_class = type(
        "ConfiguredUFIDPostgresRequestHandler",
        (UFIDPostgresRequestHandler,),
        {
            "database_url": args.database_url,
            "web_root": web_root,
            "secure_cookies": not bool(args.insecure_cookies),
        },
    )
    server = ThreadingHTTPServer((args.host, args.port), handler_class)
    print(f"UFID PostgreSQL API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UFID PostgreSQL API")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
