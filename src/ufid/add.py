from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import logging
import mimetypes
from pathlib import Path, PurePosixPath
from typing import Any

from ufid import api_client
from ufid.archives import (
    is_supported_archive_payload,
    iter_archive_entries,
    iter_archive_payload_entries,
    looks_like_archive_path,
)
from ufid.database import (
    add_archive_member,
    add_file_metadata,
    connect,
    upsert_file_identity,
)
from ufid.hashing import (
    DEFAULT_ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    compute_bytes_hashes,
    compute_file_hashes,
    iter_input_files,
)
from ufid.paths import default_sqlite_db_path


LOGGER = logging.getLogger(__name__)
MAX_NESTED_ARCHIVE_DEPTH = 128
ARCHIVE_ERROR_METADATA_NAME = "archive_error"


@dataclass
class ArchiveScanResult:
    member_count: int = 0
    error_count: int = 0

    def add(self, other: "ArchiveScanResult") -> None:
        self.member_count += other.member_count
        self.error_count += other.error_count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-add",
        description="Compute file hashes and add or enrich UFID records.",
    )
    parser.add_argument("input", help="File or directory to add")
    parser.add_argument(
        "--db",
        default=str(default_sqlite_db_path()),
        help="SQLite database path for local writes.",
    )
    parser.add_argument(
        "--backend",
        help="UFID backend base URL, for example http://127.0.0.1:8765",
    )
    parser.add_argument(
        "--api-token",
        help="Bearer token for --backend. Defaults to UFID_API_TOKEN or saved login.",
    )
    parser.add_argument("--description", help="Human-readable file description")
    parser.add_argument("--content-type", help="Content or MIME type")
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Additional metadata. Can be repeated.",
    )
    parser.add_argument(
        "--algorithm",
        action="append",
        choices=SUPPORTED_ALGORITHMS,
        help="Hash algorithm to compute. Can be repeated.",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not recurse when input is a directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    return parser


def parse_metadata(items: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Metadata must be KEY=VALUE: {item}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Metadata key cannot be empty: {item}")
        metadata[key] = value
    return metadata


def add_input(args: argparse.Namespace) -> list[dict[str, Any]]:
    algorithms = tuple(args.algorithm or DEFAULT_ALGORITHMS)
    metadata = parse_metadata(args.metadata)
    files = iter_input_files(args.input, recursive=not args.no_recursive)
    results: list[dict[str, Any]] = []

    local_connection = None
    if not args.backend:
        local_connection = connect(args.db)

    try:
        for file_path in files:
            hash_result = compute_file_hashes(file_path, algorithms=algorithms)
            content_type = args.content_type or mimetypes.guess_type(file_path)[0]
            payload = {
                "display_name": Path(file_path).name,
                "size_bytes": hash_result.size_bytes,
                "description": args.description,
                "content_type": content_type,
                "hashes": hash_result.hashes,
                "metadata": metadata,
            }

            if args.backend:
                response = api_client.upsert_file(
                    args.backend,
                    payload,
                    api_token=args.api_token,
                )
                file_id = response["id"]
                created = bool(response["created"])
                enriched = bool(response["enriched"])
                archive_scan = add_archive_contents_to_backend(
                    backend=args.backend,
                    archive_path=file_path,
                    parent_file_id=file_id,
                    algorithms=algorithms,
                    api_token=args.api_token,
                )
            else:
                assert local_connection is not None
                result = upsert_file_identity(local_connection, **payload)
                file_id = result.file_id
                created = result.created
                enriched = result.enriched
                archive_scan = add_archive_contents_to_local(
                    connection=local_connection,
                    archive_path=file_path,
                    parent_file_id=file_id,
                    algorithms=algorithms,
                )

            results.append(
                {
                    "path": str(hash_result.path),
                    "file_id": file_id,
                    "created": created,
                    "enriched": enriched,
                    "hashes": hash_result.hashes,
                    "archive_members": archive_scan.member_count,
                    "archive_errors": archive_scan.error_count,
                }
            )
    finally:
        if local_connection is not None:
            local_connection.close()

    return results


def add_archive_contents_to_local(
    *,
    connection,
    archive_path: Path,
    parent_file_id: int,
    algorithms: tuple[str, ...],
) -> ArchiveScanResult:
    entries = iter_archive_entries(archive_path)
    if not entries:
        return ArchiveScanResult()

    return add_archive_entries_to_local(
        connection=connection,
        entries=entries,
        parent_file_id=parent_file_id,
        algorithms=algorithms,
        seen_archive_file_ids={parent_file_id},
        depth=0,
    )


def add_archive_entries_to_local(
    *,
    connection,
    entries,
    parent_file_id: int,
    algorithms: tuple[str, ...],
    seen_archive_file_ids: set[int],
    depth: int,
) -> ArchiveScanResult:
    scan = ArchiveScanResult()
    for entry in entries:
        if entry.error:
            _record_archive_error_local(
                connection,
                file_id=parent_file_id,
                archive_path=entry.archive_path,
                error=entry.error,
            )
            scan.error_count += 1
            continue

        if entry.is_empty_directory:
            if add_archive_member(
                connection,
                parent_file_id=parent_file_id,
                child_file_id=None,
                archive_path=entry.archive_path,
            ):
                scan.member_count += 1
            continue

        if entry.payload is None:
            continue

        size_bytes, hashes = compute_bytes_hashes(entry.payload, algorithms=algorithms)
        child = upsert_file_identity(
            connection,
            display_name=PurePosixPath(entry.archive_path or "").name or None,
            size_bytes=size_bytes,
            hashes=hashes,
            content_type=mimetypes.guess_type(entry.archive_path or "")[0],
            metadata=[
                {
                    "metadata_type": "text",
                    "name": "archive_path",
                    "value": entry.archive_path or "",
                    "notes": f"Path inside archive UFID {parent_file_id}",
                }
            ]
            if entry.archive_path
            else None,
        )
        if add_archive_member(
            connection,
            parent_file_id=parent_file_id,
            child_file_id=child.file_id,
            archive_path=entry.archive_path,
        ):
            scan.member_count += 1

        is_nested_archive = is_supported_archive_payload(entry.payload) or looks_like_archive_path(
            entry.archive_path
        )
        if (
            depth < MAX_NESTED_ARCHIVE_DEPTH
            and child.file_id not in seen_archive_file_ids
            and is_nested_archive
        ):
            nested_entries = iter_archive_payload_entries(
                entry.payload,
                name_hint=entry.archive_path,
            )
            if nested_entries:
                scan.add(
                    add_archive_entries_to_local(
                        connection=connection,
                        entries=nested_entries,
                        parent_file_id=child.file_id,
                        algorithms=algorithms,
                        seen_archive_file_ids=seen_archive_file_ids | {child.file_id},
                        depth=depth + 1,
                    )
                )
            else:
                _record_archive_error_local(
                    connection,
                    file_id=child.file_id,
                    archive_path=entry.archive_path,
                    error="Nested archive could not be opened; no suitable extractor was available",
                )
                scan.error_count += 1
        elif looks_like_archive_path(entry.archive_path) and not is_nested_archive:
            _record_archive_error_local(
                connection,
                file_id=child.file_id,
                archive_path=entry.archive_path,
                error="Nested archive could not be opened; it may be corrupt or unsupported",
            )
            scan.error_count += 1
        elif (
            looks_like_archive_path(entry.archive_path)
            and depth >= MAX_NESTED_ARCHIVE_DEPTH
        ):
            _record_archive_error_local(
                connection,
                file_id=child.file_id,
                archive_path=entry.archive_path,
                error=f"Nested archive depth limit reached ({MAX_NESTED_ARCHIVE_DEPTH})",
            )
            scan.error_count += 1
    return scan


def add_archive_contents_to_backend(
    *,
    backend: str,
    archive_path: Path,
    parent_file_id: int,
    algorithms: tuple[str, ...],
    api_token: str | None = None,
) -> ArchiveScanResult:
    entries = iter_archive_entries(archive_path)
    if not entries:
        return ArchiveScanResult()

    return add_archive_entries_to_backend(
        backend=backend,
        entries=entries,
        parent_file_id=parent_file_id,
        algorithms=algorithms,
        seen_archive_file_ids={parent_file_id},
        depth=0,
        api_token=api_token,
    )


def add_archive_entries_to_backend(
    *,
    backend: str,
    entries,
    parent_file_id: int,
    algorithms: tuple[str, ...],
    seen_archive_file_ids: set[int],
    depth: int,
    api_token: str | None = None,
) -> ArchiveScanResult:
    scan = ArchiveScanResult()
    for entry in entries:
        if entry.error:
            _record_archive_error_backend(
                backend,
                file_id=parent_file_id,
                archive_path=entry.archive_path,
                error=entry.error,
                api_token=api_token,
            )
            scan.error_count += 1
            continue

        if entry.is_empty_directory:
            response = api_client.add_archive_member(
                backend,
                parent_file_id=parent_file_id,
                child_file_id=None,
                archive_path=entry.archive_path,
                api_token=api_token,
            )
            scan.member_count += int(bool(response.get("created")))
            continue

        if entry.payload is None:
            continue

        size_bytes, hashes = compute_bytes_hashes(entry.payload, algorithms=algorithms)
        child_payload = {
            "display_name": PurePosixPath(entry.archive_path or "").name or None,
            "size_bytes": size_bytes,
            "description": None,
            "content_type": mimetypes.guess_type(entry.archive_path or "")[0],
            "hashes": hashes,
            "metadata": [
                {
                    "metadata_type": "text",
                    "name": "archive_path",
                    "value": entry.archive_path or "",
                    "notes": f"Path inside archive UFID {parent_file_id}",
                }
            ]
            if entry.archive_path
            else None,
        }
        child_response = api_client.upsert_file(
            backend,
            child_payload,
            api_token=api_token,
        )
        response = api_client.add_archive_member(
            backend,
            parent_file_id=parent_file_id,
            child_file_id=child_response["id"],
            archive_path=entry.archive_path,
            api_token=api_token,
        )
        scan.member_count += int(bool(response.get("created")))

        child_file_id = int(child_response["id"])
        is_nested_archive = is_supported_archive_payload(entry.payload) or looks_like_archive_path(
            entry.archive_path
        )
        if (
            depth < MAX_NESTED_ARCHIVE_DEPTH
            and child_file_id not in seen_archive_file_ids
            and is_nested_archive
        ):
            nested_entries = iter_archive_payload_entries(
                entry.payload,
                name_hint=entry.archive_path,
            )
            if nested_entries:
                scan.add(
                    add_archive_entries_to_backend(
                        backend=backend,
                        entries=nested_entries,
                        parent_file_id=child_file_id,
                        algorithms=algorithms,
                        seen_archive_file_ids=seen_archive_file_ids | {child_file_id},
                        depth=depth + 1,
                        api_token=api_token,
                    )
                )
            else:
                _record_archive_error_backend(
                    backend,
                    file_id=child_file_id,
                    archive_path=entry.archive_path,
                    error="Nested archive could not be opened; no suitable extractor was available",
                    api_token=api_token,
                )
                scan.error_count += 1
        elif looks_like_archive_path(entry.archive_path) and not is_nested_archive:
            _record_archive_error_backend(
                backend,
                file_id=child_file_id,
                archive_path=entry.archive_path,
                error="Nested archive could not be opened; it may be corrupt or unsupported",
                api_token=api_token,
            )
            scan.error_count += 1
        elif (
            looks_like_archive_path(entry.archive_path)
            and depth >= MAX_NESTED_ARCHIVE_DEPTH
        ):
            _record_archive_error_backend(
                backend,
                file_id=child_file_id,
                archive_path=entry.archive_path,
                error=f"Nested archive depth limit reached ({MAX_NESTED_ARCHIVE_DEPTH})",
                api_token=api_token,
            )
            scan.error_count += 1
    return scan


def _record_archive_error_local(
    connection,
    *,
    file_id: int,
    archive_path: str | None,
    error: str,
) -> None:
    LOGGER.warning(
        "Archive scan error recorded locally: file_id=%s path=%s error=%s",
        file_id,
        archive_path,
        error,
    )
    add_file_metadata(
        connection,
        file_id=file_id,
        metadata=[_archive_error_metadata(archive_path, error)],
    )


def _record_archive_error_backend(
    backend: str,
    *,
    file_id: int,
    archive_path: str | None,
    error: str,
    api_token: str | None = None,
) -> None:
    LOGGER.warning(
        "Archive scan error recorded through backend: file_id=%s path=%s error=%s",
        file_id,
        archive_path,
        error,
    )
    api_client.add_file_metadata(
        backend,
        file_id=file_id,
        metadata=[_archive_error_metadata(archive_path, error)],
        api_token=api_token,
    )


def _archive_error_metadata(
    archive_path: str | None,
    error: str,
) -> dict[str, str]:
    value = f"{archive_path}: {error}" if archive_path else error
    return {
        "metadata_type": "text",
        "name": ARCHIVE_ERROR_METADATA_NAME,
        "value": value,
        "notes": "Archive scanner could not extract this content",
    }


def print_human(results: list[dict[str, Any]]) -> None:
    for item in results:
        action = "created" if item["created"] else "enriched" if item["enriched"] else "unchanged"
        archive_suffix = ""
        if item.get("archive_members"):
            archive_suffix = f", {item['archive_members']} archive members"
        if item.get("archive_errors"):
            archive_suffix += f", {item['archive_errors']} archive scan errors"
        print(f"{item['path']}: UFID {item['file_id']} {action}{archive_suffix}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        results = add_input(args)
    except Exception as exc:
        parser.exit(2, f"ufid-add: {exc}\n")

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        print_human(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
