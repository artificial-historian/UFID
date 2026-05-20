from __future__ import annotations

import argparse
from contextlib import closing
import getpass
import json
from typing import Any

from ufid import api_client
from ufid.database import connect as sqlite_connect, create_user as create_sqlite_user
from ufid.postgres_database import connect as postgres_connect, create_user as create_postgres_user


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-auth",
        description="Manage UFID API login sessions and bootstrap users.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login", help="Log in to a UFID API")
    login_parser.add_argument("--backend", required=True, help="UFID API base URL")
    login_parser.add_argument("--username", required=True)
    login_parser.add_argument("--password", help="Prompted when omitted")
    login_parser.add_argument("--json", action="store_true")

    logout_parser = subparsers.add_parser("logout", help="Log out from a UFID API")
    logout_parser.add_argument("--backend", required=True, help="UFID API base URL")
    logout_parser.add_argument("--json", action="store_true")

    whoami_parser = subparsers.add_parser("whoami", help="Show current API session")
    whoami_parser.add_argument("--backend", required=True, help="UFID API base URL")
    whoami_parser.add_argument("--json", action="store_true")

    create_parser = subparsers.add_parser(
        "create-user",
        help="Create a user directly in SQLite or PostgreSQL",
    )
    create_parser.add_argument("--db", help="SQLite database path")
    create_parser.add_argument("--database-url", help="PostgreSQL DSN")
    create_parser.add_argument("--username", required=True)
    create_parser.add_argument("--password", help="Prompted when omitted")
    create_parser.add_argument("--display-name")
    create_parser.add_argument(
        "--role",
        action="append",
        default=[],
        choices=["reader", "contributor", "curator", "admin"],
        help="Role to grant. Can be repeated.",
    )
    create_parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "login":
            result = _login(args)
        elif args.command == "logout":
            result = api_client.logout(args.backend)
        elif args.command == "whoami":
            result = api_client.get_session(args.backend)
        elif args.command == "create-user":
            result = _create_user(args)
        else:
            raise ValueError(f"unknown command: {args.command}")
    except Exception as exc:
        parser.exit(2, f"ufid-auth: {exc}\n")

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(args.command, result)
    return 0


def _login(args: argparse.Namespace) -> dict[str, Any]:
    password = args.password or getpass.getpass("UFID password: ")
    return api_client.login(
        args.backend,
        username=args.username,
        password=password,
        save=True,
    )


def _create_user(args: argparse.Namespace) -> dict[str, Any]:
    if bool(args.db) == bool(args.database_url):
        raise ValueError("provide exactly one of --db or --database-url")
    password = args.password or getpass.getpass("New UFID password: ")
    if args.database_url:
        with postgres_connect(args.database_url) as connection:
            user = create_postgres_user(
                connection,
                username=args.username,
                password=password,
                display_name=args.display_name,
                roles=args.role or ["reader"],
            )
    else:
        with closing(sqlite_connect(args.db)) as connection:
            user = create_sqlite_user(
                connection,
                username=args.username,
                password=password,
                display_name=args.display_name,
                roles=args.role or ["reader"],
            )
    return {"user": _public_user(user)}


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name"),
        "roles": list(user.get("roles") or []),
    }


def _print_human(command: str, result: dict[str, Any]) -> None:
    if command == "login":
        user = result["user"]
        print(
            f"Logged in to UFID as {user['username']} "
            f"({', '.join(user.get('roles') or [])})"
        )
        return
    if command == "logout":
        print("Logged out" if result.get("revoked") else "No active session")
        return
    if command == "whoami":
        if not result.get("authenticated"):
            print("Not authenticated")
            return
        user = result["user"]
        print(f"{user['username']} ({', '.join(user.get('roles') or [])})")
        return
    if command == "create-user":
        user = result["user"]
        print(f"Created UFID user {user['username']} ({', '.join(user['roles'])})")


if __name__ == "__main__":
    raise SystemExit(main())
