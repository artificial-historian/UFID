from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class UFIDAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.payload = dict(payload or {})


def login(
    base_url: str,
    *,
    username: str,
    password: str,
    save: bool = True,
    timeout: float = 30,
) -> dict[str, Any]:
    payload = _post_json(
        f"{base_url.rstrip('/')}/api/v1/auth/login",
        {"username": username, "password": password},
        timeout=timeout,
    )
    token = payload.get("token")
    if save and isinstance(token, str):
        save_session(base_url, token, payload)
    return payload


def logout(base_url: str, timeout: float = 30) -> dict[str, Any]:
    payload = _post_json(
        f"{base_url.rstrip('/')}/api/v1/auth/logout",
        {},
        timeout=timeout,
        base_url=base_url,
    )
    clear_session(base_url)
    return payload


def get_session(
    base_url: str,
    timeout: float = 30,
    *,
    api_token: str | None = None,
) -> dict[str, Any]:
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/auth/session",
        headers=_auth_headers(base_url, api_token=api_token),
        method="GET",
    )
    return _request_json(request, timeout=timeout)


def create_user(
    base_url: str,
    *,
    username: str,
    password: str,
    roles: list[str],
    display_name: str | None = None,
    timeout: float = 30,
    api_token: str | None = None,
) -> dict[str, Any]:
    return _post_json(
        f"{base_url.rstrip('/')}/api/v1/auth/users",
        {
            "username": username,
            "password": password,
            "display_name": display_name,
            "roles": roles,
        },
        timeout=timeout,
        base_url=base_url,
        api_token=api_token,
    )


def find_file_by_hash(
    base_url: str,
    algorithm: str,
    hash_value: str,
    size_bytes: int | None = None,
    timeout: float = 30,
    api_token: str | None = None,
) -> dict[str, Any] | None:
    params: dict[str, str | int] = {"algorithm": algorithm, "value": hash_value}
    if size_bytes is not None:
        params["size"] = size_bytes
    query = urlencode(params)
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/files/by-hash?{query}",
        headers=_auth_headers(base_url, api_token=api_token),
        method="GET",
    )
    payload = _request_json(request, timeout=timeout)
    if payload.get("found"):
        return payload["file"]
    return None


def upsert_file(
    base_url: str,
    payload: Mapping[str, Any],
    timeout: float = 30,
    api_token: str | None = None,
) -> dict[str, Any]:
    return _post_json(
        f"{base_url.rstrip('/')}/api/v1/files",
        payload,
        timeout=timeout,
        base_url=base_url,
        api_token=api_token,
    )


def add_archive_member(
    base_url: str,
    *,
    parent_file_id: int,
    child_file_id: int | None,
    archive_path: str | None,
    timeout: float = 30,
    api_token: str | None = None,
) -> dict[str, Any]:
    return _post_json(
        f"{base_url.rstrip('/')}/api/v1/archive-members",
        {
            "parent_file_id": parent_file_id,
            "child_file_id": child_file_id,
            "archive_path": archive_path,
        },
        timeout=timeout,
        base_url=base_url,
        api_token=api_token,
    )


def add_file_metadata(
    base_url: str,
    *,
    file_id: int,
    metadata: Mapping[str, Any] | list[Mapping[str, Any]],
    timeout: float = 30,
    api_token: str | None = None,
) -> dict[str, Any]:
    return _post_json(
        f"{base_url.rstrip('/')}/api/v1/files/{file_id}/metadata",
        {"metadata": metadata},
        timeout=timeout,
        base_url=base_url,
        api_token=api_token,
    )


def import_dat_file_identities(
    base_url: str,
    *,
    filename: str | None,
    text: str,
    timeout: float = 30,
    api_token: str | None = None,
) -> dict[str, Any]:
    return _post_json(
        f"{base_url.rstrip('/')}/api/v1/files/import-dat",
        {"filename": filename, "text": text},
        timeout=timeout,
        base_url=base_url,
        api_token=api_token,
    )


def _post_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
    base_url: str | None = None,
    api_token: str | None = None,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            **(_auth_headers(base_url, api_token=api_token) if base_url else {}),
        },
        method="POST",
    )
    return _request_json(request, timeout=timeout)


def _auth_headers(base_url: str | None, *, api_token: str | None = None) -> dict[str, str]:
    token = api_token or os.environ.get("UFID_API_TOKEN")
    if not token and base_url:
        token = load_session_token(base_url)
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def save_session(base_url: str, token: str, payload: Mapping[str, Any]) -> None:
    path = session_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    sessions = _read_session_store()
    sessions[_normalize_base_url(base_url)] = {
        "token": token,
        "user": payload.get("user"),
        "expires_at": payload.get("expires_at"),
    }
    path.write_text(json.dumps(sessions, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_session_token(base_url: str) -> str | None:
    session = _read_session_store().get(_normalize_base_url(base_url))
    if not isinstance(session, dict):
        return None
    token = session.get("token")
    return token if isinstance(token, str) and token else None


def clear_session(base_url: str) -> None:
    path = session_store_path()
    sessions = _read_session_store()
    sessions.pop(_normalize_base_url(base_url), None)
    if sessions:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sessions, indent=2, sort_keys=True), encoding="utf-8")
    elif path.exists():
        try:
            path.unlink()
        except OSError:
            path.write_text("{}", encoding="utf-8")


def session_store_path() -> Path:
    configured = os.environ.get("UFID_SESSION_FILE")
    if configured:
        return Path(configured)
    return Path.home() / ".ufid" / "sessions.json"


def _read_session_store() -> dict[str, Any]:
    path = session_store_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def _request_json(request, *, timeout: float) -> dict[str, Any]:
    try:
        with urlopen(request, timeout=timeout) as response:
            return _decode_json_response(response.read())
    except HTTPError as exc:
        raw = _read_http_error_body(exc)
        try:
            payload = _decode_json_response(raw)
            message = str(payload.get("error") or exc.reason or exc)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
            message = raw.decode("utf-8", errors="replace") or str(exc.reason or exc)
        raise UFIDAPIError(
            f"UFID API request failed ({exc.code}): {message}",
            status=exc.code,
            payload=payload,
        ) from exc
    except URLError as exc:
        raise UFIDAPIError(f"UFID API request failed: {exc.reason}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UFIDAPIError("UFID API returned invalid JSON") from exc


def _decode_json_response(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise json.JSONDecodeError("JSON object is required", raw.decode("utf-8"), 0)
    return payload


def _read_http_error_body(exc: HTTPError) -> bytes:
    try:
        return exc.read()
    finally:
        exc.close()
