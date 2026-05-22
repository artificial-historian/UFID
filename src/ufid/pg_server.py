from __future__ import annotations

import argparse
from http.cookies import SimpleCookie
import json
import logging
import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from ufid import postgres_database as database
from ufid.auth import DEFAULT_SESSION_SECONDS, SESSION_COOKIE_NAME
from ufid.database import IdentityConflict
from ufid.goldrush import parse_logiqx_dat
from ufid.paths import resolve_web_root
from ufid.server import (
    _auth_removal_action_path,
    _auth_user_action_path,
    _auth_user_delete_path,
    _coerce_metadata_payload,
    _coerce_payload_size,
    _coerce_positive_id,
    _bounded_list_limit,
    _int_query_value,
    _optional_int_query_value,
    _public_registration_dict,
    _public_user_dict,
    _read_json_payload,
    _registration_response,
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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
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
        if parsed.path == "/api/v1/auth/registration/validate":
            self._handle_registration_validate(parsed.query)
            return
        if parsed.path == "/api/v1/auth/me":
            if not self._require_authenticated():
                return
            self._handle_auth_me()
            return
        if parsed.path == "/api/v1/auth/users":
            if not self._require_role("admin"):
                return
            self._handle_list_users()
            return
        if parsed.path == "/api/v1/auth/removal-requests":
            if not self._require_role("admin"):
                return
            self._handle_list_removal_requests(parsed.query)
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

    def do_DELETE(self) -> None:
        try:
            self._dispatch_delete()
        except Exception as exc:
            self._handle_unexpected_error(exc)

    def _dispatch_post(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/auth/register":
            self._handle_register_user()
            return
        if parsed.path == "/api/v1/auth/registration/complete":
            self._handle_registration_complete()
            return
        if parsed.path == "/api/v1/auth/login":
            self._handle_auth_login()
            return
        if parsed.path == "/api/v1/auth/logout":
            self._handle_auth_logout()
            return
        if parsed.path == "/api/v1/auth/me/password":
            if not self._require_authenticated():
                return
            self._handle_change_password()
            return
        if parsed.path == "/api/v1/auth/me/removal-request":
            if not self._require_authenticated():
                return
            self._handle_request_removal()
            return
        if parsed.path == "/api/v1/auth/users":
            if not self._require_role("admin"):
                return
            self._handle_create_user()
            return
        user_action = _auth_user_action_path(parsed.path)
        if user_action is not None:
            if not self._require_role("admin"):
                return
            user_id, action = user_action
            self._handle_user_action(user_id, action)
            return
        removal_action = _auth_removal_action_path(parsed.path)
        if removal_action is not None:
            if not self._require_role("admin"):
                return
            request_id, action = removal_action
            self._handle_removal_request_action(request_id, action)
            return
        if parsed.path == "/api/v1/files":
            if not self._require_role("contributor"):
                return
            self._handle_upsert_file()
            return
        if parsed.path == "/api/v1/goldrush/alerts":
            if not self._require_role("contributor"):
                return
            self._handle_goldrush_alerts_post()
            return
        if parsed.path == "/api/v1/goldrush/alerts/clear":
            if not self._require_role("contributor"):
                return
            self._handle_clear_goldrush_alerts()
            return
        if parsed.path == "/api/v1/goldrush/import-dat":
            if not self._require_role("contributor"):
                return
            self._handle_import_goldrush_dat()
            return
        if parsed.path == "/api/v1/goldrush/matches/search":
            if not self._require_role("reader"):
                return
            self._handle_search_goldrush_matches()
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

    def _dispatch_delete(self) -> None:
        parsed = urlparse(self.path)
        user_id = _auth_user_delete_path(parsed.path)
        if user_id is not None:
            if not self._require_role("admin"):
                return
            self._handle_delete_user(user_id)
            return
        if parsed.path == "/api/v1/goldrush/alerts":
            if not self._require_role("contributor"):
                return
            self._handle_clear_goldrush_alerts()
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

    def _handle_auth_me(self) -> None:
        current_user = self._current_user()
        assert current_user is not None
        with database.connect(self.database_url) as connection:
            profile = database.get_user_by_id(connection, current_user.id)
            removal_request = database.get_user_removal_request(connection, current_user.id)
        if profile is None:
            self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self._write_json(
            {
                "user": _public_user_dict(profile),
                "removal_request": removal_request,
            }
        )

    def _handle_register_user(self) -> None:
        try:
            payload = self._read_json()
            with database.connect(self.database_url) as connection:
                user = database.register_user(
                    connection,
                    username=str(payload.get("username") or ""),
                    password=str(payload.get("password") or ""),
                    display_name=payload.get("display_name"),
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

        self._write_json(
            {
                "registered": True,
                "requires_activation": True,
                "user": _public_user_dict(user),
            },
            status=HTTPStatus.CREATED,
        )

    def _handle_registration_validate(self, query: str) -> None:
        token = _single_query_value(parse_qs(query), "token") or ""
        if not token:
            self._write_json({"error": "token is required"}, status=HTTPStatus.BAD_REQUEST)
            return
        with database.connect(self.database_url) as connection:
            registration = database.get_registration_token(connection, token)
        if registration is None:
            self._write_json({"error": "Invalid or expired registration link"}, status=HTTPStatus.NOT_FOUND)
            return
        self._write_json({"registration": _public_registration_dict(registration)})

    def _handle_registration_complete(self) -> None:
        try:
            payload = self._read_json()
            token = str(payload.get("token") or "")
            if not token:
                raise ValueError("token is required")
            with database.connect(self.database_url) as connection:
                user = database.complete_registration(
                    connection,
                    token=token,
                    password=str(payload.get("password") or ""),
                    display_name=payload.get("display_name"),
                )
                if user is None:
                    self._write_json(
                        {"error": "Invalid or expired registration link"},
                        status=HTTPStatus.NOT_FOUND,
                    )
                    return
                session_token, session_user = database.create_session(
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
                "completed": True,
                "authenticated": True,
                "token": session_token,
                "token_type": "Bearer",
                "expires_at": session_user.expires_at,
                "user": session_user.to_public_dict(),
            },
            headers=[
                (
                    "Set-Cookie",
                    self._session_cookie_header(session_token, DEFAULT_SESSION_SECONDS),
                )
            ],
        )

    def _handle_change_password(self) -> None:
        current_user = self._current_user()
        assert current_user is not None
        try:
            payload = self._read_json()
            current_password = str(payload.get("current_password") or "")
            new_password = str(payload.get("new_password") or "")
            if not current_password:
                raise ValueError("current_password is required")
            with database.connect(self.database_url) as connection:
                changed = database.change_user_password(
                    connection,
                    user_id=current_user.id,
                    current_password=current_password,
                    new_password=new_password,
                    keep_token=self._session_token(),
                )
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        if not changed:
            self._write_json({"error": "Current password is incorrect"}, status=HTTPStatus.FORBIDDEN)
            return
        self._write_json({"changed": True})

    def _handle_request_removal(self) -> None:
        current_user = self._current_user()
        assert current_user is not None
        with database.connect(self.database_url) as connection:
            request = database.request_user_removal(connection, user_id=current_user.id)
        self._write_json({"request": request}, status=HTTPStatus.CREATED)

    def _handle_list_users(self) -> None:
        with database.connect(self.database_url) as connection:
            users = database.list_users(connection)
        self._write_json({"users": [_public_user_dict(user) for user in users], "count": len(users)})

    def _handle_create_user(self) -> None:
        try:
            payload = self._read_json()
            roles = payload.get("roles") or ["reader"]
            if not isinstance(roles, list):
                raise ValueError("roles must be a list")
            password = str(payload.get("password") or "")
            current_user = self._current_user()
            created_by = current_user.id if current_user is not None else None
            with database.connect(self.database_url) as connection:
                if password:
                    user = database.create_user(
                        connection,
                        username=str(payload.get("username") or ""),
                        password=password,
                        display_name=payload.get("display_name"),
                        roles=[str(role) for role in roles],
                        activate=bool(payload.get("activate", True)),
                        registration_completed=True,
                    )
                    response = {"user": _public_user_dict(user)}
                else:
                    user, token, registration = database.create_invited_user(
                        connection,
                        username=str(payload.get("username") or ""),
                        display_name=payload.get("display_name"),
                        roles=[str(role) for role in roles],
                        created_by_user_id=created_by,
                    )
                    response = {
                        "user": _public_user_dict(user),
                        "registration": _registration_response(self, token, registration),
                    }
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

        self._write_json(response, status=HTTPStatus.CREATED)

    def _handle_user_action(self, user_id: int, action: str) -> None:
        current_user = self._current_user()
        try:
            with database.connect(self.database_url) as connection:
                if action == "activate":
                    user = database.set_user_activation(connection, user_id=user_id, active=True)
                    if user is None:
                        self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                        return
                    self._write_json({"user": _public_user_dict(user)})
                    return
                if action == "deactivate":
                    if current_user is not None and user_id == current_user.id:
                        self._write_json(
                            {"error": "Admins cannot deactivate their own account"},
                            status=HTTPStatus.BAD_REQUEST,
                        )
                        return
                    user = database.set_user_activation(connection, user_id=user_id, active=False)
                    if user is None:
                        self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                        return
                    self._write_json({"user": _public_user_dict(user)})
                    return
                if action == "roles":
                    payload = self._read_json()
                    roles = payload.get("roles")
                    if not isinstance(roles, list):
                        raise ValueError("roles must be a list")
                    role_names = [str(role) for role in roles]
                    if (
                        current_user is not None
                        and user_id == current_user.id
                        and "admin"
                        not in {role.strip().lower() for role in role_names}
                    ):
                        self._write_json(
                            {"error": "Admins cannot remove their own admin role"},
                            status=HTTPStatus.BAD_REQUEST,
                        )
                        return
                    user = database.update_user_roles(
                        connection,
                        user_id=user_id,
                        roles=role_names,
                    )
                    if user is None:
                        self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                        return
                    self._write_json({"user": _public_user_dict(user)})
                    return
                if action == "invite":
                    if database.get_user_by_id(connection, user_id) is None:
                        self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                        return
                    token, registration = database.create_registration_token(
                        connection,
                        user_id=user_id,
                        created_by_user_id=current_user.id if current_user else None,
                    )
                    self._write_json(
                        {"registration": _registration_response(self, token, registration)}
                    )
                    return
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_delete_user(self, user_id: int) -> None:
        current_user = self._current_user()
        if current_user is not None and user_id == current_user.id:
            self._write_json(
                {"error": "Admins cannot delete their own account"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return
        with database.connect(self.database_url) as connection:
            deleted = database.delete_user(connection, user_id)
        if not deleted:
            self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self._write_json({"deleted": True, "user_id": user_id})

    def _handle_list_removal_requests(self, query: str) -> None:
        params = parse_qs(query)
        status = _single_query_value(params, "status") or "pending"
        try:
            with database.connect(self.database_url) as connection:
                requests = database.list_user_removal_requests(connection, status=status)
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        self._write_json({"requests": requests, "count": len(requests)})

    def _handle_removal_request_action(self, request_id: int, action: str) -> None:
        current_user = self._current_user()
        assert current_user is not None
        try:
            payload = self._read_json()
        except (ValueError, json.JSONDecodeError):
            payload = {}
        notes = payload.get("notes")
        notes = None if notes is None else str(notes)
        with database.connect(self.database_url) as connection:
            request = database.get_user_removal_request_by_id(connection, request_id)
            if request is None:
                self._write_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
                return
            if int(request["user_id"]) == current_user.id and action == "approve":
                self._write_json(
                    {"error": "Admins cannot approve their own removal request"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            if action == "approve":
                result = database.approve_user_removal_request(
                    connection,
                    request_id=request_id,
                    decided_by_user_id=current_user.id,
                    notes=notes,
                )
            elif action == "block":
                result = database.block_user_removal_request(
                    connection,
                    request_id=request_id,
                    decided_by_user_id=current_user.id,
                    notes=notes,
                )
            else:
                result = None
        if result is None:
            self._write_json({"error": "Removal request is not pending"}, status=HTTPStatus.BAD_REQUEST)
            return
        self._write_json({"request": result})

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
            limit = _bounded_list_limit(limit)
            sort_by = (_single_query_value(params, "sort") or "id").strip().lower()
            sort_direction = (_single_query_value(params, "direction") or "desc").strip().lower()
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        search = _single_query_value(params, "q")
        try:
            with database.connect(self.database_url) as connection:
                files = database.list_files(
                    connection,
                    limit=limit,
                    offset=offset,
                    query=search,
                    sort_by=sort_by,
                    sort_direction=sort_direction,
                )
                total_count = database.count_files(connection, query=search)
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
        user_id = self._registered_user_id()
        if user_id is None:
            return
        params = parse_qs(query)
        try:
            limit = _bounded_list_limit(_int_query_value(params, "limit", default=200))
            offset = _int_query_value(params, "offset", default=0)
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        search = _single_query_value(params, "q")
        with database.connect(self.database_url) as connection:
            alerts = database.list_goldrush_alerts(
                connection,
                user_id=user_id,
                limit=limit,
                offset=offset,
                query=search,
            )
            total_count = database.count_goldrush_alerts(connection, user_id=user_id, query=search)
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
        user_id = self._registered_user_id()
        if user_id is None:
            return
        with database.connect(self.database_url) as connection:
            sources = database.list_goldrush_alert_sources(connection, user_id=user_id)
        self._write_json({"sources": sources, "count": len(sources)})

    def _handle_list_goldrush_matches(self, query: str) -> None:
        user_id = self._registered_user_id()
        if user_id is None:
            return
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
        with database.connect(self.database_url) as connection:
            matches = database.list_goldrush_matches(
                connection,
                user_id=user_id,
                limit=limit,
                offset=offset,
                query=search,
                source_keys=source_keys,
            )
            total_count = database.count_goldrush_matches(
                connection,
                user_id=user_id,
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

    def _handle_goldrush_alerts_post(self) -> None:
        try:
            payload = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        if str(payload.get("action") or "").strip().lower() == "clear":
            self._handle_clear_goldrush_alerts()
            return
        self._handle_create_goldrush_alert(payload)

    def _handle_create_goldrush_alert(self, payload: Mapping[str, Any]) -> None:
        user_id = self._registered_user_id()
        if user_id is None:
            return
        try:
            hashes = payload.get("hashes")
            if not isinstance(hashes, dict) or not hashes:
                raise ValueError("hashes object is required")
            with database.connect(self.database_url) as connection:
                result = database.create_goldrush_alert(
                    connection,
                    user_id=user_id,
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
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            status, message = _postgres_constraint_response(exc)
            if status is not None:
                self._write_json({"error": message}, status=status)
                return
            raise

        self._write_json(
            result,
            status=HTTPStatus.CREATED if result["created"] else HTTPStatus.OK,
        )

    def _handle_import_goldrush_dat(self) -> None:
        user_id = self._registered_user_id()
        if user_id is None:
            return
        try:
            payload = self._read_json()
            dat_text = payload.get("text") or payload.get("content") or payload.get("dat")
            if not isinstance(dat_text, str) or not dat_text.strip():
                raise ValueError("text is required")
            filename = payload.get("filename") or payload.get("name")
            filename = None if filename is None else str(filename)
            parsed = parse_logiqx_dat(dat_text, filename=filename)
            with database.connect(self.database_url) as connection:
                result = database.import_goldrush_alerts(
                    connection,
                    user_id=user_id,
                    alerts=parsed.alerts,
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

        response = {
            "source_name": parsed.source_name,
            "parsed": len(parsed.alerts),
            **result,
        }
        status = HTTPStatus.CREATED if result["created"] else HTTPStatus.OK
        if result["valid"] == 0 and result["errors"]:
            status = HTTPStatus.BAD_REQUEST
        self._write_json(response, status=status)

    def _handle_clear_goldrush_alerts(self) -> None:
        user_id = self._registered_user_id()
        if user_id is None:
            return
        with database.connect(self.database_url) as connection:
            deleted = database.clear_goldrush_alerts(connection, user_id=user_id)
        self._write_json({"deleted": deleted})

    def _handle_search_goldrush_matches(self) -> None:
        user_id = self._registered_user_id()
        if user_id is None:
            return
        with database.connect(self.database_url) as connection:
            result = database.scan_goldrush_matches(connection, user_id=user_id)
            total_count = database.count_goldrush_matches(connection, user_id=user_id)
        self._write_json({"search": result, "total_count": total_count})

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

    def _require_authenticated(self) -> bool:
        user = self._current_user()
        if user is None:
            self._write_json({"error": "Authentication required"}, status=HTTPStatus.UNAUTHORIZED)
            return False
        return True

    def _require_role(self, role: str) -> bool:
        user = self._current_user()
        if user is None:
            self._write_json({"error": "Authentication required"}, status=HTTPStatus.UNAUTHORIZED)
            return False
        if not _user_has_role(user.roles, role):
            self._write_json({"error": "Insufficient role"}, status=HTTPStatus.FORBIDDEN)
            return False
        return True

    def _registered_user_id(self) -> int | None:
        user = self._current_user()
        if user is None:
            self._write_json({"error": "Authentication required"}, status=HTTPStatus.UNAUTHORIZED)
            return None
        if user.id <= 0:
            self._write_json(
                {"error": "Goldrush alerts require a registered user"},
                status=HTTPStatus.FORBIDDEN,
            )
            return None
        return user.id

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

    def _absolute_url(self, path: str) -> str:
        host = self.headers.get("Host") or f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        forwarded_proto = self.headers.get("X-Forwarded-Proto")
        scheme = (
            forwarded_proto.split(",", 1)[0].strip()
            if forwarded_proto
            else ("https" if self.secure_cookies else "http")
        )
        normalized_path = path if path.startswith("/") else f"/{path}"
        return f"{scheme}://{host}{normalized_path}"

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
