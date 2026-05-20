from __future__ import annotations

import argparse
from contextlib import closing, redirect_stderr, redirect_stdout
import getpass
from http.client import HTTPConnection, HTTPException
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import threading
import time
from typing import TextIO

from ufid import ia_ingest
from ufid.database import connect, create_user
from ufid.paths import default_user_data_dir, resolve_web_root, source_root
from ufid.server import UFIDRequestHandler


class Tee:
    def __init__(self, *streams: TextIO) -> None:
        self.streams = streams

    def write(self, data: str) -> int:
        for stream in self.streams:
            stream.write(data)
            stream.flush()
        return len(data)

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()

    def isatty(self) -> bool:
        return bool(self.streams and getattr(self.streams[0], "isatty", lambda: False)())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-local-ia-discovery",
        description=(
            "Start a local SQLite UFID web/API server and run Internet Archive "
            "metadata discovery against local SQLite state."
        ),
    )
    parser.add_argument(
        "--data-dir",
        help=(
            "Directory for SQLite databases, IA cache, and logs. Defaults to "
            "UFID_DATA_DIR, ufid.config.toml, or the current user's local UFID "
            "data directory."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--port-scan-count",
        type=int,
        default=20,
        help="Try this many consecutive ports when the requested port is occupied.",
    )
    parser.add_argument("--collection", default=ia_ingest.DEFAULT_COLLECTION)
    parser.add_argument("--query")
    parser.add_argument("--crawl-name")
    parser.add_argument("--max-items", type=int)
    parser.add_argument("--scrape-count", type=int, default=1000)
    parser.add_argument("--request-delay", type=float, default=0.25)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--max-retries", type=int, default=5)
    parser.add_argument("--user-agent")
    parser.add_argument(
        "--discover-collections",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Also scrape child IA collections discovered in search results "
            "(mediatype=collection). Enabled by default; pass "
            "--no-discover-collections to disable."
        ),
    )
    parser.add_argument("--collection-depth", type=int, default=1)
    parser.add_argument("--max-collections", type=int)
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--jsonl", action="store_true")
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Show step-by-step IA metadata queue details, including declared "
            "file hashes captured from the IA API."
        ),
    )
    parser.add_argument("--no-server", action="store_true")
    parser.add_argument("--keep-server-running", action="store_true")
    parser.add_argument("--create-admin", action="store_true")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Start and health-check the local server, then exit without IA discovery.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data_dir = (
        Path(args.data_dir).expanduser()
        if args.data_dir
        else default_user_data_dir()
    ).resolve()
    db_path = data_dir / "ufid.sqlite"
    state_db = data_dir / "ia-ingest.sqlite"
    cache_dir = data_dir / "ia-cache"
    logs_dir = data_dir / "logs"
    discovery_log = logs_dir / "ia-discovery.log"

    cache_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    print("UFID local Windows IA discovery")
    print(f"Source root:   {source_root()}")
    print(f"UFID SQLite:   {db_path}")
    print(f"IA state DB:   {state_db}")
    print(f"IA cache:      {cache_dir}")
    print(f"Requested URL: http://{args.host}:{args.port}")
    print(f"IA query:      {args.query or f'collection:{args.collection}'}")
    if args.discover_collections:
        print(
            "IA collections: discovery enabled "
            f"(depth={max(0, args.collection_depth)}"
            + (
                f", max={args.max_collections}"
                if args.max_collections is not None
                else ""
            )
            + ")"
        )
    else:
        print("IA collections: discovery disabled")
    print("")

    if args.create_admin:
        create_local_admin(
            db_path=db_path,
            username=args.admin_username,
            password=args.admin_password,
        )

    server: ThreadingHTTPServer | None = None
    server_thread: threading.Thread | None = None
    local_api_token = secrets.token_urlsafe(32)
    try:
        if not args.no_server:
            server, server_thread, actual_port = start_server(
                host=args.host,
                port=args.port,
                port_scan_count=args.port_scan_count,
                db_path=db_path,
                web_root=resolve_web_root(None),
                local_api_token=local_api_token,
            )
            args.port = actual_port
            print(f"UFID server is healthy at http://{args.host}:{args.port}")
            print("")

        if args.check_only:
            print("Check-only mode complete.")
            return 0

        print("Starting Internet Archive discovery mode (metadata queue only).")
        print("Press Ctrl+C to stop discovery.")
        print(f"Discovery log: {discovery_log}")
        print("")

        discovery_args = build_discovery_args(
            args=args,
            db_path=db_path,
            state_db=state_db,
            cache_dir=cache_dir,
            backend_url=None
            if args.no_server
            else f"http://{args.host}:{args.port}",
            api_token=None if args.no_server else local_api_token,
        )
        with discovery_log.open("a", encoding="utf-8") as log_file:
            tee_stdout = Tee(sys.stdout, log_file)
            tee_stderr = Tee(sys.stderr, log_file)
            with redirect_stdout(tee_stdout), redirect_stderr(tee_stderr):
                return ia_ingest.main(discovery_args)
    finally:
        if server is not None:
            if args.keep_server_running:
                print("Keeping the server alive. Press Ctrl+C to stop it.")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
            server.shutdown()
            server.server_close()
            if server_thread is not None:
                server_thread.join(timeout=5)

    return 0


def create_local_admin(*, db_path: Path, username: str, password: str | None) -> None:
    if not password:
        password = getpass.getpass(f"Password for local UFID user '{username}': ")
    try:
        with closing(connect(db_path)) as connection:
            create_user(
                connection,
                username=username,
                password=password,
                roles=["reader", "contributor", "admin"],
            )
        print(f"Created local UFID user '{username}'.")
    except sqlite3.IntegrityError:
        print(f"Local UFID user '{username.lower()}' already exists.")


def start_server(
    *,
    host: str,
    port: int,
    port_scan_count: int,
    db_path: Path,
    web_root: Path,
    local_api_token: str | None = None,
) -> tuple[ThreadingHTTPServer, threading.Thread, int]:
    connect(db_path).close()
    handler_class = type(
        "WindowsLocalUFIDRequestHandler",
        (UFIDRequestHandler,),
        {
            "db_path": db_path,
            "web_root": web_root,
            "secure_cookies": False,
            "local_api_token": local_api_token,
            "local_api_roles": ("reader", "contributor", "admin"),
        },
    )

    errors: list[str] = []
    scan_count = max(1, port_scan_count)
    candidate_ports = [port + offset for offset in range(scan_count)] if port else [0]
    for candidate_port in candidate_ports:
        try:
            server = ThreadingHTTPServer((host, candidate_port), handler_class)
        except OSError as exc:
            errors.append(f"{host}:{candidate_port} bind failed: {exc}")
            continue

        actual_port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ok, detail = wait_for_health(host=host, port=actual_port)
        if ok:
            if port == 0:
                print(f"Using ephemeral port {actual_port}.")
            elif actual_port != port:
                print(
                    f"Requested port {port} was not usable; using {actual_port} instead."
                )
            return server, thread, actual_port

        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        errors.append(f"{host}:{actual_port} health failed: {detail}")

    joined = "\n  ".join(errors[-10:])
    raise RuntimeError(
        "UFID local server did not become healthy on any scanned port. "
        f"Tried {host}:{port} through {host}:{port + scan_count - 1}.\n  {joined}"
    )


def wait_for_health(*, host: str, port: int, attempts: int = 40) -> tuple[bool, str]:
    last_error = "no attempts made"
    for attempt in range(1, attempts + 1):
        connection: HTTPConnection | None = None
        try:
            connection = HTTPConnection(host, port, timeout=2)
            connection.request("GET", "/health", headers={"Host": f"{host}:{port}"})
            response = connection.getresponse()
            raw = response.read()
            server_header = response.getheader("Server", "")
            if response.status == 200:
                payload = json.loads(raw.decode("utf-8"))
                if isinstance(payload, dict) and payload.get("ok") is True:
                    return True, "ok"
            preview = raw[:200].decode("utf-8", errors="replace").replace("\n", "\\n")
            last_error = (
                f"attempt {attempt}: HTTP {response.status} from "
                f"{server_header or 'unknown server'} body={preview!r}"
            )
        except (HTTPException, json.JSONDecodeError, UnicodeDecodeError) as exc:
            last_error = f"attempt {attempt}: {exc.__class__.__name__}: {exc}"
        except OSError as exc:
            last_error = f"attempt {attempt}: {exc.__class__.__name__}: {exc}"
        finally:
            if connection is not None:
                connection.close()
        if attempt < attempts:
            time.sleep(0.5)
    return False, last_error


def build_discovery_args(
    *,
    args: argparse.Namespace,
    db_path: Path,
    state_db: Path,
    cache_dir: Path,
    backend_url: str | None = None,
    api_token: str | None = None,
) -> list[str]:
    discovery_args = [
        "--mode",
        "metadata",
        "--state-db",
        str(state_db),
        "--cache",
        str(cache_dir),
        "--scrape-count",
        str(args.scrape_count),
        "--request-delay",
        str(args.request_delay),
        "--timeout",
        str(args.timeout),
        "--max-retries",
        str(args.max_retries),
    ]
    if backend_url:
        discovery_args.extend(["--backend", backend_url])
    else:
        discovery_args.extend(["--db", str(db_path)])
    if api_token:
        discovery_args.extend(["--api-token", api_token])
    if args.query:
        discovery_args.extend(["--query", args.query])
    else:
        discovery_args.extend(["--collection", args.collection])
    if args.crawl_name:
        discovery_args.extend(["--crawl-name", args.crawl_name])
    if args.max_items and args.max_items > 0:
        discovery_args.extend(["--max-items", str(args.max_items)])
    if args.user_agent:
        discovery_args.extend(["--user-agent", args.user_agent])
    if args.discover_collections:
        discovery_args.append("--discover-collections")
    else:
        discovery_args.append("--no-discover-collections")
    discovery_args.extend(["--collection-depth", str(args.collection_depth)])
    if args.max_collections is not None:
        discovery_args.extend(["--max-collections", str(args.max_collections)])
    if args.retry_failed:
        discovery_args.append("--retry-failed")
    if args.jsonl:
        discovery_args.append("--jsonl")
    if args.debug:
        discovery_args.append("--debug")
    return discovery_args


if __name__ == "__main__":
    raise SystemExit(main())
