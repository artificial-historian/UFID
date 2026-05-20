from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
import gzip
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
import zlib

from ufid import __version__


LOGGER = logging.getLogger(__name__)

ARCHIVE_BASE_URL = "https://archive.org"
SCRAPE_ENDPOINT = f"{ARCHIVE_BASE_URL}/services/search/v1/scrape"
METADATA_ENDPOINT = f"{ARCHIVE_BASE_URL}/metadata"
RETRY_STATUSES = {429, 500, 502, 503, 504}
DEFAULT_USER_AGENT = (
    f"UFID-IA-Ingest/{__version__} (gpt-5; purpose: archive.org-to-ufid-ingest)"
)


class IAClientError(RuntimeError):
    """Base error for Internet Archive client operations."""


class IAHTTPError(IAClientError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        url: str | None = None,
        payload: object | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.url = url
        self.payload = payload


class IAMetadataError(IAClientError):
    def __init__(
        self,
        message: str,
        *,
        identifier: str,
        errcode: int | None = None,
    ) -> None:
        super().__init__(message)
        self.identifier = identifier
        self.errcode = errcode


class IAItemNotFound(IAMetadataError):
    """Raised when the Internet Archive metadata API reports a missing item."""


class IADownloadError(IAClientError):
    """Raised when an Internet Archive file download cannot be completed."""


class IAChecksumMismatch(IADownloadError):
    def __init__(
        self,
        message: str,
        *,
        algorithm: str,
        expected: str,
        actual: str,
    ) -> None:
        super().__init__(message)
        self.algorithm = algorithm
        self.expected = expected
        self.actual = actual


@dataclass(frozen=True)
class IAFile:
    name: str
    source: str | None = None
    format: str | None = None
    size: int | None = None
    mtime: int | None = None
    md5: str | None = None
    sha1: str | None = None
    crc32: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IAItem:
    identifier: str
    mediatype: str | None = None
    title: str | None = None
    collections: tuple[str, ...] = ()
    files: tuple[IAFile, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DownloadResult:
    path: Path
    url: str
    bytes_written: int
    resumed: bool


class RateLimiter:
    def __init__(
        self,
        min_delay_seconds: float,
        *,
        sleep_func: Callable[[float], None] = time.sleep,
    ) -> None:
        self.min_delay_seconds = max(0.0, float(min_delay_seconds))
        self.sleep_func = sleep_func
        self._next_allowed_at = 0.0

    def wait(self) -> None:
        if self.min_delay_seconds <= 0:
            return
        now = time.monotonic()
        if now < self._next_allowed_at:
            self.sleep_func(self._next_allowed_at - now)
            now = time.monotonic()
        self._next_allowed_at = now + self.min_delay_seconds

    def wait_retry_after(self, value: str | None, fallback: float) -> None:
        delay = _retry_after_seconds(value)
        if delay is None:
            delay = fallback
        if delay > 0:
            self.sleep_func(delay)
        self._next_allowed_at = time.monotonic() + self.min_delay_seconds


class IAHTTPClient:
    def __init__(
        self,
        *,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 60,
        max_retries: int = 5,
        request_delay_seconds: float = 0.25,
        download_delay_seconds: float = 0.5,
        sleep_func: Callable[[float], None] = time.sleep,
    ) -> None:
        user_agent = user_agent.strip()
        if not user_agent:
            raise ValueError("A descriptive Internet Archive User-Agent is required")
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.request_limiter = RateLimiter(
            request_delay_seconds,
            sleep_func=sleep_func,
        )
        self.download_limiter = RateLimiter(
            download_delay_seconds,
            sleep_func=sleep_func,
        )

    def scrape(
        self,
        *,
        query: str,
        fields: list[str],
        count: int = 1000,
        cursor: str | None = None,
        sorts: list[str] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str | int] = {
            "q": query,
            "fields": ",".join(fields),
            "count": max(100, int(count)),
        }
        if cursor:
            params["cursor"] = cursor
        if sorts:
            params["sorts"] = ",".join(sorts)
        data = self.get_json(SCRAPE_ENDPOINT, params=params)
        items = data.get("items")
        if items is not None and not isinstance(items, list):
            raise IAHTTPError("Scrape API returned non-list items", payload=data)
        return data

    def get_metadata(self, identifier: str) -> dict[str, Any]:
        url = f"{METADATA_ENDPOINT}/{quote_identifier(identifier)}"
        data = self.get_json_any(url, params={"extended_err": "1"})
        if data == []:
            raise IAItemNotFound(
                f"Internet Archive item not found: {identifier}",
                identifier=identifier,
            )
        if isinstance(data, dict) and "error" in data:
            raise IAMetadataError(
                str(data["error"]),
                identifier=identifier,
                errcode=_coerce_int(data.get("errcode")),
            )
        if not isinstance(data, dict):
            raise IAMetadataError(
                f"Unexpected metadata response type: {type(data).__name__}",
                identifier=identifier,
            )
        return data

    def parse_item(self, identifier: str) -> IAItem:
        return parse_item_metadata(identifier, self.get_metadata(identifier))

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
    ) -> dict[str, Any]:
        data = self.get_json_any(url, params=params)
        if not isinstance(data, dict):
            raise IAHTTPError(
                f"Expected JSON object from {url}, got {type(data).__name__}",
                url=url,
                payload=data,
            )
        return data

    def get_json_any(
        self,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
    ) -> object:
        request_url = build_url(url, params)
        raw, headers = self._request_bytes(
            request_url,
            limiter=self.request_limiter,
            extra_headers={
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate",
            },
        )
        try:
            decoded = _decode_response_bytes(raw, headers.get("Content-Encoding"))
            return json.loads(decoded.decode("utf-8"))
        except (OSError, zlib.error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IAHTTPError(f"Invalid JSON from {request_url}", url=request_url) from exc

    def download_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        destination: Path,
        resume: bool = True,
    ) -> DownloadResult:
        destination.parent.mkdir(parents=True, exist_ok=True)
        part_path = destination.with_name(destination.name + ".part")
        url = file_url(identifier, ia_file.name)
        attempts = self.max_retries + 1
        last_error: BaseException | None = None

        for attempt in range(1, attempts + 1):
            existing = part_path.stat().st_size if resume and part_path.exists() else 0
            headers = {"Accept-Encoding": "identity"}
            if existing:
                headers["Range"] = f"bytes={existing}-"
            request = Request(url, headers=self._headers(headers), method="GET")

            try:
                self.download_limiter.wait()
                with urlopen(request, timeout=self.timeout) as response:
                    status = getattr(response, "status", response.getcode())
                    if existing and status == 206:
                        mode = "ab"
                        resumed = True
                    else:
                        mode = "wb"
                        resumed = False
                        existing = 0

                    bytes_written = existing
                    with part_path.open(mode) as output:
                        while True:
                            chunk = response.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
                            bytes_written += len(chunk)

                if ia_file.size is not None and bytes_written != ia_file.size:
                    raise IADownloadError(
                        f"Downloaded size mismatch for {identifier}/{ia_file.name}: "
                        f"expected {ia_file.size}, got {bytes_written}"
                    )
                os.replace(part_path, destination)
                return DownloadResult(
                    path=destination,
                    url=url,
                    bytes_written=bytes_written,
                    resumed=resumed,
                )
            except HTTPError as exc:
                code = exc.code
                reason = exc.reason
                retry_after = exc.headers.get("Retry-After")
                try:
                    if code == 416 and ia_file.size is not None and part_path.exists():
                        if part_path.stat().st_size == ia_file.size:
                            os.replace(part_path, destination)
                            return DownloadResult(
                                path=destination,
                                url=url,
                                bytes_written=ia_file.size,
                                resumed=True,
                            )
                finally:
                    exc.close()
                last_error = exc
                if code not in RETRY_STATUSES or attempt >= attempts:
                    raise IADownloadError(
                        f"Download failed for {identifier}/{ia_file.name} "
                        f"({code}): {reason}"
                    ) from exc
                self.download_limiter.wait_retry_after(
                    retry_after,
                    _backoff_seconds(attempt),
                )
            except (OSError, URLError, TimeoutError, IADownloadError) as exc:
                last_error = exc
                if attempt >= attempts:
                    raise IADownloadError(
                        f"Download failed for {identifier}/{ia_file.name}: {exc}"
                    ) from exc
                self.download_limiter.wait_retry_after(None, _backoff_seconds(attempt))

        raise IADownloadError(
            f"Download failed for {identifier}/{ia_file.name}: {last_error}"
        )

    def _request_bytes(
        self,
        url: str,
        *,
        limiter: RateLimiter,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[bytes, Mapping[str, str]]:
        attempts = self.max_retries + 1
        for attempt in range(1, attempts + 1):
            request = Request(
                url,
                headers=self._headers(extra_headers or {}),
                method="GET",
            )
            try:
                limiter.wait()
                with urlopen(request, timeout=self.timeout) as response:
                    return response.read(), response.headers
            except HTTPError as exc:
                raw = _read_http_error_body(exc)
                code = exc.code
                retry_after = exc.headers.get("Retry-After")
                if code not in RETRY_STATUSES or attempt >= attempts:
                    payload = _try_decode_json(raw, exc.headers.get("Content-Encoding"))
                    message = _http_error_message(code, exc.reason, payload)
                    raise IAHTTPError(
                        message,
                        status=code,
                        url=url,
                        payload=payload,
                    ) from exc
                LOGGER.warning(
                    "Internet Archive request retry: status=%s url=%s attempt=%s",
                    code,
                    url,
                    attempt,
                )
                limiter.wait_retry_after(
                    retry_after,
                    _backoff_seconds(attempt),
                )
            except (OSError, URLError, TimeoutError) as exc:
                if attempt >= attempts:
                    raise IAHTTPError(f"Internet Archive request failed: {exc}", url=url) from exc
                LOGGER.warning(
                    "Internet Archive request retry: error=%s url=%s attempt=%s",
                    exc,
                    url,
                    attempt,
                )
                limiter.wait_retry_after(None, _backoff_seconds(attempt))

        raise IAHTTPError(f"Internet Archive request failed: {url}", url=url)

    def _headers(self, extra: Mapping[str, str]) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            **dict(extra),
        }


def parse_item_metadata(identifier: str, data: Mapping[str, Any]) -> IAItem:
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    assert isinstance(metadata, dict)
    collections = normalize_collection(metadata.get("collection"))
    files = tuple(
        parse_file(file_data)
        for file_data in data.get("files", [])
        if isinstance(file_data, dict) and file_data.get("name")
    )
    return IAItem(
        identifier=identifier,
        mediatype=_optional_str(metadata.get("mediatype")),
        title=_optional_str(metadata.get("title")),
        collections=collections,
        files=files,
        raw=dict(data),
    )


def parse_file(data: Mapping[str, Any]) -> IAFile:
    return IAFile(
        name=str(data["name"]),
        source=_optional_str(data.get("source")),
        format=_optional_str(data.get("format")),
        size=_coerce_int(data.get("size")),
        mtime=_coerce_int(data.get("mtime")),
        md5=_optional_lower_hex(data.get("md5")),
        sha1=_optional_lower_hex(data.get("sha1")),
        crc32=_optional_lower_hex(data.get("crc32")),
        raw=dict(data),
    )


def normalize_collection(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value if item)
    return (str(value),)


def file_url(identifier: str, filename: str) -> str:
    return (
        f"{ARCHIVE_BASE_URL}/download/"
        f"{quote_identifier(identifier)}/{quote(filename, safe='/')}"
    )


def quote_identifier(identifier: str) -> str:
    return quote(identifier, safe="")


def build_url(url: str, params: Mapping[str, str | int] | None = None) -> str:
    if not params:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params)}"


def safe_download_path(root: Path, identifier: str, filename: str) -> Path:
    item_dir = _safe_path_component(identifier)
    parts = [
        _safe_path_component(part)
        for part in filename.replace("\\", "/").split("/")
        if part not in ("", ".", "..")
    ]
    if not parts:
        raise ValueError(f"Unsafe Internet Archive filename: {filename!r}")

    root = root.resolve()
    candidate = root.joinpath(item_dir, *parts).resolve()
    if root != candidate and root not in candidate.parents:
        raise ValueError(f"Internet Archive filename escapes cache root: {filename!r}")
    return candidate


def is_metadata_file(ia_file: IAFile) -> bool:
    name = ia_file.name.lower()
    return (
        ia_file.format == "Metadata"
        or name.endswith("_meta.xml")
        or name.endswith("_files.xml")
        or name.endswith("_reviews.xml")
        or name.endswith("_itemimage.jpg")
    )


def verify_declared_fixity(
    *,
    identifier: str,
    ia_file: IAFile,
    hashes: Mapping[str, str],
) -> None:
    checks = (
        ("sha1", ia_file.sha1),
        ("md5", ia_file.md5),
        ("crc32", ia_file.crc32),
    )
    for algorithm, expected in checks:
        if not expected:
            continue
        actual = hashes.get(algorithm)
        if not actual:
            continue
        if actual.lower() != expected.lower():
            raise IAChecksumMismatch(
                f"Internet Archive declared {algorithm} mismatch for "
                f"{identifier}/{ia_file.name}: expected {expected}, got {actual}",
                algorithm=algorithm,
                expected=expected,
                actual=actual,
            )


def _safe_path_component(value: str) -> str:
    cleaned = "".join(
        "_" if character in '<>:"|?*' or ord(character) < 32 else character
        for character in value
    ).strip(" .")
    if not cleaned:
        cleaned = "_"
    reserved = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
    if cleaned.lower() in reserved:
        cleaned = f"_{cleaned}"
    return cleaned[:180]


def _decode_response_bytes(raw: bytes, encoding: str | None) -> bytes:
    if not encoding:
        return raw
    normalized = encoding.lower()
    if normalized == "gzip":
        return gzip.decompress(raw)
    if normalized == "deflate":
        return zlib.decompress(raw)
    return raw


def _try_decode_json(raw: bytes, encoding: str | None) -> object | None:
    try:
        decoded = _decode_response_bytes(raw, encoding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return None


def _http_error_message(code: int, reason: str, payload: object | None) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"Internet Archive request failed ({code}): {payload['error']}"
    return f"Internet Archive request failed ({code}): {reason}"


def _read_http_error_body(exc: HTTPError) -> bytes:
    try:
        return exc.read()
    finally:
        exc.close()


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    delay = parsed.timestamp() - time.time()
    return max(0.0, delay)


def _backoff_seconds(attempt: int) -> float:
    return min(60.0, 2 ** max(0, attempt - 1))


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_lower_hex(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def _coerce_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
