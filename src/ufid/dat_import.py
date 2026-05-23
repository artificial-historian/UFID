from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
from typing import Any

from ufid import api_client
from ufid.database import connect, import_dat_file_identities
from ufid.goldrush import parse_logiqx_dat
from ufid.paths import default_sqlite_db_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-dat-import",
        description="Import full Logiqx DAT file identities into UFID records.",
    )
    parser.add_argument("input", help="Logiqx DAT file in XML or classic syntax.")
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
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    return parser


def import_dat(args: argparse.Namespace) -> dict[str, Any]:
    dat_path = Path(args.input)
    text = dat_path.read_text(encoding="utf-8-sig")
    filename = dat_path.name
    if args.backend:
        return api_client.import_dat_file_identities(
            args.backend,
            filename=filename,
            text=text,
            api_token=args.api_token,
        )

    parsed = parse_logiqx_dat(text, filename=filename)
    with closing(connect(args.db)) as connection:
        result = import_dat_file_identities(
            connection,
            records=parsed.alerts,
            dat_filename=filename,
        )
    return {
        "source_name": parsed.source_name,
        "parsed": len(parsed.alerts),
        **result,
    }


def print_human(result: dict[str, Any]) -> None:
    print(
        (
            f"{result['source_name']}: parsed {result['parsed']}, "
            f"created {result['created']}, enriched {result['enriched']}, "
            f"unchanged {result['unchanged']}, skipped {result['skipped']}"
        )
    )
    for error in result.get("errors", [])[:10]:
        prefix = f"row {error.get('index')}"
        name = error.get("name")
        if name:
            prefix = f"{prefix} ({name})"
        print(f"{prefix}: {error.get('error')}")
    if len(result.get("errors", [])) > 10:
        print(f"... {len(result['errors']) - 10} more skipped rows")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = import_dat(args)
    except Exception as exc:
        parser.exit(2, f"ufid-dat-import: {exc}\n")

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_human(result)
    if result["valid"] == 0 and result["errors"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
