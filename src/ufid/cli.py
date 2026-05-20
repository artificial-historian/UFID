from __future__ import annotations

import sys

from ufid import __version__
from ufid.add import main as add_main
from ufid.archive_tools_setup import main as archive_tools_main
from ufid.auth_cli import main as auth_main
from ufid.ia_ingest import main as ia_ingest_main
from ufid.local_ia_discovery import main as local_ia_discovery_main
from ufid.lookup import main as lookup_main
from ufid.pg_server import main as pg_server_main
from ufid.server import main as server_main


COMMANDS = {
    "add": add_main,
    "archive-tools": archive_tools_main,
    "auth": auth_main,
    "ia-ingest": ia_ingest_main,
    "local-ia-discovery": local_ia_discovery_main,
    "lookup": lookup_main,
    "pg-server": pg_server_main,
    "server": server_main,
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"--version", "-V"}:
        print(f"ufid {__version__}")
        return 0
    if not args or args[0] not in COMMANDS:
        names = ", ".join(sorted(COMMANDS))
        print(f"Usage: ufid <{names}> [args...]", file=sys.stderr)
        print("Use 'ufid --version' to show the installed version.", file=sys.stderr)
        return 2

    command = args.pop(0)
    return COMMANDS[command](args)


if __name__ == "__main__":
    raise SystemExit(main())
