from __future__ import annotations

import argparse
from contextlib import closing
import json
from typing import Any

from ufid import api_client
from ufid.database import connect, find_file_by_hash
from ufid.hashing import DEFAULT_ALGORITHMS, SUPPORTED_ALGORITHMS, compute_file_hashes, iter_input_files
from ufid.paths import default_sqlite_db_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-lookup",
        description="Compute file hashes and search UFID records.",
    )
    parser.add_argument("input", help="File or directory to look up")
    parser.add_argument(
        "--db",
        default=str(default_sqlite_db_path()),
        help="SQLite database path for local lookups.",
    )
    parser.add_argument(
        "--backend",
        help="UFID backend base URL, for example http://127.0.0.1:8765",
    )
    parser.add_argument(
        "--api-token",
        help="Bearer token for --backend. Defaults to UFID_API_TOKEN or saved login.",
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


def lookup_hashes(
    hashes: dict[str, str],
    *,
    db_path: str,
    backend: str | None,
    api_token: str | None = None,
    size_bytes: int | None = None,
) -> dict[str, Any] | None:
    preferred_order = ("sha256", "blake3", "sha1", "md5", "crc32")
    ordered_algorithms = [
        algorithm for algorithm in preferred_order if algorithm in hashes
    ] + [algorithm for algorithm in hashes if algorithm not in preferred_order]

    if backend:
        for algorithm in ordered_algorithms:
            found = api_client.find_file_by_hash(
                backend,
                algorithm,
                hashes[algorithm],
                size_bytes=size_bytes,
                api_token=api_token,
            )
            if found:
                return found
        return None

    with closing(connect(db_path)) as connection:
        for algorithm in ordered_algorithms:
            found = find_file_by_hash(
                connection,
                algorithm,
                hashes[algorithm],
                size_bytes=size_bytes,
            )
            if found:
                return found
    return None


def lookup_input(args: argparse.Namespace) -> list[dict[str, Any]]:
    algorithms = tuple(args.algorithm or DEFAULT_ALGORITHMS)
    files = iter_input_files(args.input, recursive=not args.no_recursive)
    results: list[dict[str, Any]] = []
    for file_path in files:
        hash_result = compute_file_hashes(file_path, algorithms=algorithms)
        found = lookup_hashes(
            hash_result.hashes,
            db_path=args.db,
            backend=args.backend,
            api_token=args.api_token,
            size_bytes=hash_result.size_bytes,
        )
        results.append(
            {
                "path": str(hash_result.path),
                "size_bytes": hash_result.size_bytes,
                "hashes": hash_result.hashes,
                "found": found is not None,
                "file": found,
            }
        )
    return results


def print_human(results: list[dict[str, Any]]) -> None:
    for item in results:
        print(f"{item['path']} ({item['size_bytes']} bytes)")
        for algorithm, hash_value in item["hashes"].items():
            print(f"  {algorithm}: {hash_value}")
        if item["found"]:
            file_record = item["file"]
            print(f"  UFID: {file_record['id']}")
            if file_record.get("display_name"):
                print(f"  name: {file_record['display_name']}")
            if file_record.get("description"):
                print(f"  description: {file_record['description']}")
            if file_record.get("content_type"):
                print(f"  content type: {file_record['content_type']}")
            if file_record.get("metadata"):
                print("  metadata:")
                for item in file_record["metadata"]:
                    notes = f" ({item['notes']})" if item.get("notes") else ""
                    print(
                        f"    {item['metadata_type']}:{item['name']} = {item['value']}{notes}"
                    )
            if file_record.get("identity_conflicts"):
                print("  identity conflicts:")
                for conflict in file_record["identity_conflicts"]:
                    related = (
                        f" related UFID {conflict['related_file_id']}"
                        if conflict.get("related_file_id")
                        else ""
                    )
                    notes = f" ({conflict['notes']})" if conflict.get("notes") else ""
                    print(
                        "    "
                        f"{conflict['conflict_type']}:{conflict['algorithm']}"
                        f"{related} existing={conflict.get('existing_value')}"
                        f" incoming={conflict.get('incoming_value')}{notes}"
                    )
        else:
            print("  UFID: not found")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        results = lookup_input(args)
    except Exception as exc:
        parser.exit(2, f"ufid-lookup: {exc}\n")

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        print_human(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
