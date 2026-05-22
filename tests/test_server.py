from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import sys
import threading
import unittest
from urllib.parse import urlencode
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid
from contextlib import closing, redirect_stdout
from io import StringIO


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.server import UFIDRequestHandler, _coerce_metadata_payload, _is_sqlite_busy_error
from ufid.database import connect, create_user
from ufid.goldrush import parse_logiqx_dat
from ufid import add, lookup
from ufid.paths import default_user_data_dir

SCRATCH = default_user_data_dir() / "test-runs"


class ServerTests(unittest.TestCase):
    def test_metadata_payload_rejects_non_object_rows(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata item 1 must be an object"):
            _coerce_metadata_payload(
                [
                    {"metadata_type": "text", "name": "ok", "value": "yes"},
                    "not-an-object",
                ]
            )

    def test_server_health_add_lookup_browse_and_get(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-test-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        handler_class = type(
            "TestUFIDRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            health = self._get_json(f"{base_url}/health")
            token = self._login(base_url)
            created = self._post_json(
                f"{base_url}/api/v1/files",
                {
                    "display_name": "server-sample.bin",
                    "size_bytes": 4,
                    "description": "Server test sample",
                    "content_type": "application/octet-stream",
                    "hashes": {
                        "crc32": "12345678",
                        "md5": "d" * 32,
                        "sha1": "e" * 40,
                        "sha256": None,
                        "blake3": None,
                    },
                    "metadata": {"source": "server-test"},
                },
                token=token,
            )
            lookup = self._get_json(
                f"{base_url}/api/v1/files/by-hash?algorithm=sha1&value={'e' * 40}&size=4",
                token=token,
            )
            browse = self._get_json(f"{base_url}/api/v1/files?q=server-sample", token=token)
            loaded = self._get_json(f"{base_url}/api/v1/files/{created['id']}", token=token)
            archive_member = self._post_json(
                f"{base_url}/api/v1/archive-members",
                {
                    "parent_file_id": created["id"],
                    "child_file_id": None,
                    "archive_path": "empty-folder",
                },
                token=token,
            )
            metadata_added = self._post_json(
                f"{base_url}/api/v1/files/{created['id']}/metadata",
                {
                    "metadata": [
                        {
                            "metadata_type": "text",
                            "name": "archive_error",
                            "value": "encrypted.zip: encrypted member",
                        }
                    ]
                },
                token=token,
            )
            loaded_with_archive = self._get_json(
                f"{base_url}/api/v1/files/{created['id']}",
                token=token,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(health["ok"])
        self.assertTrue(created["created"])
        self.assertTrue(lookup["found"])
        self.assertEqual(lookup["count"], 1)
        self.assertEqual(browse["count"], 1)
        self.assertIn(
            "server-test",
            [item["value"] for item in loaded["file"]["metadata"]],
        )
        self.assertIsNone(loaded["file"]["hashes"]["sha256"])
        self.assertIsNone(loaded["file"]["hashes"]["blake3"])
        self.assertTrue(archive_member["created"])
        self.assertTrue(metadata_added["enriched"])
        self.assertEqual(
            loaded_with_archive["file"]["archive_members"][0]["archive_path"],
            "empty-folder",
        )
        self.assertIn(
            "encrypted.zip: encrypted member",
            [item["value"] for item in loaded_with_archive["file"]["metadata"]],
        )

    def test_file_list_supports_pagination_filtering_and_sorting(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-list-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        handler_class = type(
            "TestUFIDListRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            token = self._login(base_url)
            for index, (name, size) in enumerate(
                [("beta.bin", 30), ("alpha.bin", 10), ("gamma.bin", 20)],
                start=1,
            ):
                self._post_json(
                    f"{base_url}/api/v1/files",
                    {
                        "display_name": name,
                        "size_bytes": size,
                        "hashes": {
                            "crc32": f"{index:08x}",
                            "md5": f"{index:032x}",
                            "sha1": f"{index:040x}",
                        },
                    },
                    token=token,
                )

            page_one = self._get_json(
                f"{base_url}/api/v1/files?limit=2&sort=name&direction=asc",
                token=token,
            )
            page_two = self._get_json(
                f"{base_url}/api/v1/files?limit=2&offset=2&sort=name&direction=asc",
                token=token,
            )
            filtered = self._get_json(
                f"{base_url}/api/v1/files?q=beta&sort=size&direction=desc",
                token=token,
            )
            by_size = self._get_json(
                f"{base_url}/api/v1/files?limit=3&sort=size&direction=desc",
                token=token,
            )
            with self.assertRaises(HTTPError) as raised:
                self._get_json(f"{base_url}/api/v1/files?sort=unsupported", token=token)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(page_one["total_count"], 3)
        self.assertEqual(page_one["next_offset"], 2)
        self.assertEqual([item["display_name"] for item in page_one["files"]], ["alpha.bin", "beta.bin"])
        self.assertIsNone(page_two["next_offset"])
        self.assertEqual([item["display_name"] for item in page_two["files"]], ["gamma.bin"])
        self.assertEqual(filtered["total_count"], 1)
        self.assertEqual(filtered["files"][0]["display_name"], "beta.bin")
        self.assertEqual([item["size_bytes"] for item in by_size["files"]], [30, 20, 10])
        self.assertEqual(raised.exception.code, 400)
        raised.exception.close()

    def test_sqlite_server_handles_parallel_file_writes(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-parallel-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        handler_class = type(
            "TestUFIDParallelRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            token = self._login(base_url)

            def post_file(index: int) -> dict:
                return self._post_json(
                    f"{base_url}/api/v1/files",
                    {
                        "display_name": f"parallel-{index}.bin",
                        "size_bytes": 1000 + index,
                        "hashes": {
                            "crc32": f"{index:08x}",
                            "md5": f"{index:032x}",
                            "sha1": f"{index:040x}",
                        },
                    },
                    token=token,
                )

            with ThreadPoolExecutor(max_workers=8) as executor:
                created = list(executor.map(post_file, range(1, 17)))
            listed = self._get_json(
                f"{base_url}/api/v1/files?q=parallel&limit=20",
                token=token,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(all(item["created"] for item in created))
        self.assertEqual(listed["total_count"], 16)

    def test_sqlite_busy_errors_are_retryable(self) -> None:
        self.assertTrue(_is_sqlite_busy_error(sqlite3.OperationalError("database is locked")))
        self.assertTrue(_is_sqlite_busy_error(sqlite3.OperationalError("database table is locked")))
        self.assertFalse(_is_sqlite_busy_error(sqlite3.OperationalError("syntax error")))

    def test_goldrush_alerts_dat_import_and_matches(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-goldrush-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        with closing(connect(db_path)) as connection:
            create_user(
                connection,
                username="other",
                password="correct horse battery staple",
                roles=["reader", "contributor"],
            )
        handler_class = type(
            "TestUFIDGoldrushRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            token = self._login(base_url)
            other_token = self._post_json(
                f"{base_url}/api/v1/auth/login",
                {"username": "other", "password": "correct horse battery staple"},
            )["token"]
            created_file = self._post_json(
                f"{base_url}/api/v1/files",
                {
                    "display_name": "goldrush-target.bin",
                    "size_bytes": 5,
                    "hashes": {
                        "crc32": "11111111",
                        "md5": "a" * 32,
                        "sha1": "b" * 40,
                        "sha256": "c" * 64,
                    },
                },
                token=token,
            )
            manual_alert = self._post_json(
                f"{base_url}/api/v1/goldrush/alerts",
                {
                    "name": "Manual target",
                    "description": "Manual watch entry",
                    "size_bytes": 5,
                    "hashes": {"md5": "a" * 32},
                },
                token=token,
            )
            other_manual_alert = self._post_json(
                f"{base_url}/api/v1/goldrush/alerts",
                {
                    "name": "Manual target",
                    "description": "Manual watch entry",
                    "size_bytes": 5,
                    "hashes": {"md5": "a" * 32},
                },
                token=other_token,
            )
            duplicate_other_manual_alert = self._post_json(
                f"{base_url}/api/v1/goldrush/alerts",
                {
                    "name": "Manual target",
                    "description": "Manual watch entry",
                    "size_bytes": 5,
                    "hashes": {"md5": "a" * 32},
                },
                token=other_token,
            )
            other_alerts = self._get_json(
                f"{base_url}/api/v1/goldrush/alerts",
                token=other_token,
            )
            xml_dat = f"""<?xml version="1.0"?>
<datafile>
  <header>
    <name>Goldrush Test DAT</name>
    <description>Goldrush Test Description</description>
  </header>
  <game name="Goldrush Set">
    <description>Goldrush Set Description</description>
    <rom name="goldrush-target.bin" size="5" crc="11111111" md5="{'a' * 32}" sha1="{'b' * 40}" />
  </game>
</datafile>
"""
            dat_import = self._post_json(
                f"{base_url}/api/v1/goldrush/import-dat",
                {"filename": "goldrush-test.dat", "text": xml_dat},
                token=token,
            )
            alerts = self._get_json(
                f"{base_url}/api/v1/goldrush/alerts?q=Goldrush",
                token=token,
            )
            matches_before_search = self._get_json(
                f"{base_url}/api/v1/goldrush/matches",
                token=token,
            )
            sources = self._get_json(
                f"{base_url}/api/v1/goldrush/alert-sources",
                token=token,
            )
            source_keys = {source["source_key"] for source in sources["sources"]}
            dat_source_key = "logiqx-dat-xml|Goldrush Test DAT"
            search_result = self._post_json(
                f"{base_url}/api/v1/goldrush/matches/search",
                {},
                token=token,
            )
            duplicate_search_result = self._post_json(
                f"{base_url}/api/v1/goldrush/matches/search",
                {},
                token=token,
            )
            manual_matches = self._get_json(
                f"{base_url}/api/v1/goldrush/matches?q=Manual",
                token=token,
            )
            dat_matches = self._get_json(
                f"{base_url}/api/v1/goldrush/matches?q=Goldrush%20Set",
                token=token,
            )
            manual_source_matches = self._get_json(
                f"{base_url}/api/v1/goldrush/matches?source_key=manual",
                token=token,
            )
            dat_source_matches = self._get_json(
                f"{base_url}/api/v1/goldrush/matches?{urlencode({'source_key': dat_source_key})}",
                token=token,
            )
            with self.assertRaises(HTTPError) as raised:
                self._post_json(
                    f"{base_url}/api/v1/goldrush/alerts",
                    {
                        "name": "Invalid",
                        "description": "Missing hashes",
                        "hashes": {},
                    },
                    token=token,
                )
            cleared = self._post_json(
                f"{base_url}/api/v1/goldrush/alerts",
                {"action": "clear"},
                token=token,
            )
            alerts_after_clear = self._get_json(
                f"{base_url}/api/v1/goldrush/alerts",
                token=token,
            )
            matches_after_clear = self._get_json(
                f"{base_url}/api/v1/goldrush/matches",
                token=token,
            )
            sources_after_clear = self._get_json(
                f"{base_url}/api/v1/goldrush/alert-sources",
                token=token,
            )
            other_alerts_after_clear = self._get_json(
                f"{base_url}/api/v1/goldrush/alerts",
                token=other_token,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(created_file["created"], True)
        self.assertTrue(manual_alert["created"])
        self.assertTrue(other_manual_alert["created"])
        self.assertFalse(duplicate_other_manual_alert["created"])
        self.assertEqual(other_alerts["total_count"], 1)
        self.assertEqual(manual_alert["alert"]["hashes"]["md5"], "a" * 32)
        self.assertEqual(dat_import["source_name"], "Goldrush Test DAT")
        self.assertEqual(dat_import["parsed"], 1)
        self.assertEqual(dat_import["created"], 1)
        self.assertEqual(alerts["total_count"], 1)
        self.assertEqual(alerts["alerts"][0]["name"], "Goldrush Set")
        self.assertEqual(alerts["alerts"][0]["description"], "Goldrush Test DAT")
        self.assertEqual(matches_before_search["total_count"], 0)
        self.assertEqual(search_result["search"], {"matched": 2, "created": 2})
        self.assertEqual(search_result["total_count"], 2)
        self.assertEqual(
            duplicate_search_result["search"],
            {"matched": 2, "created": 0},
        )
        self.assertEqual(duplicate_search_result["total_count"], 2)
        self.assertEqual(manual_matches["total_count"], 1)
        self.assertEqual(manual_matches["matches"][0]["file"]["id"], created_file["id"])
        self.assertEqual(manual_matches["matches"][0]["matched_algorithms"], ["md5"])
        self.assertEqual(dat_matches["total_count"], 1)
        self.assertEqual(
            dat_matches["matches"][0]["matched_algorithms"],
            ["crc32", "md5", "sha1"],
        )
        self.assertTrue(dat_matches["matches"][0]["size_matched"])
        self.assertEqual(sources["count"], 2)
        self.assertEqual(source_keys, {"manual", "logiqx-dat-xml|Goldrush Test DAT"})
        self.assertEqual(manual_source_matches["total_count"], 1)
        self.assertEqual(
            manual_source_matches["matches"][0]["alert"]["name"],
            "Manual target",
        )
        self.assertEqual(dat_source_matches["total_count"], 1)
        self.assertEqual(
            dat_source_matches["matches"][0]["alert"]["name"],
            "Goldrush Set",
        )
        self.assertEqual(raised.exception.code, 400)
        raised.exception.close()
        self.assertEqual(cleared["deleted"], 2)
        self.assertEqual(alerts_after_clear["total_count"], 0)
        self.assertEqual(matches_after_clear["total_count"], 0)
        self.assertEqual(sources_after_clear["count"], 0)
        self.assertEqual(other_alerts_after_clear["total_count"], 1)

    def test_classic_logiqx_dat_parser(self) -> None:
        summary = parse_logiqx_dat(
            """
clrmamepro (
  name "Classic DAT"
  description "Classic DAT Description"
)
game (
  name "Classic Set"
  rom ( name "classic.bin" size 7 crc 22222222 md5 dddddddddddddddddddddddddddddddd sha1 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee )
)
"""
        )

        self.assertEqual(summary.source_name, "Classic DAT")
        self.assertEqual(len(summary.alerts), 1)
        alert = summary.alerts[0]
        self.assertEqual(alert["name"], "Classic Set")
        self.assertEqual(alert["description"], "Classic DAT")
        self.assertEqual(alert["source_detail"], "classic.bin")
        self.assertEqual(alert["hashes"]["crc32"], "22222222")

    def test_server_reports_optional_hash_conflict_payload(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-conflict-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        handler_class = type(
            "TestUFIDConflictRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            token = self._login(base_url)
            created = self._post_json(
                f"{base_url}/api/v1/files",
                {
                    "display_name": "server-conflict.bin",
                    "size_bytes": 4,
                    "hashes": {
                        "crc32": "12345678",
                        "md5": "d" * 32,
                        "sha1": "e" * 40,
                        "sha256": "a" * 64,
                    },
                },
                token=token,
            )
            with self.assertRaises(HTTPError) as raised:
                self._post_json(
                    f"{base_url}/api/v1/files",
                    {
                        "display_name": "server-conflict.bin",
                        "size_bytes": 4,
                        "hashes": {
                            "crc32": "12345678",
                            "md5": "d" * 32,
                            "sha1": "e" * 40,
                            "sha256": "b" * 64,
                        },
                    },
                    token=token,
                )
            conflict_payload = json.loads(raised.exception.read().decode("utf-8"))
            raised.exception.close()
            loaded = self._get_json(f"{base_url}/api/v1/files/{created['id']}", token=token)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(raised.exception.code, 409)
        self.assertEqual(conflict_payload["file_id"], created["id"])
        self.assertEqual(conflict_payload["conflict_type"], "optional_hash_mismatch")
        self.assertEqual(
            loaded["file"]["identity_conflicts"][0]["conflict_type"],
            "optional_hash_mismatch",
        )

    def test_server_requires_authentication_for_api(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-auth-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        handler_class = type(
            "TestUFIDAuthRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            with self.assertRaises(HTTPError) as raised:
                self._get_json(f"{base_url}/api/v1/files")
            token = self._login(base_url)
            session = self._get_json(f"{base_url}/api/v1/auth/session", token=token)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(raised.exception.code, 401)
        raised.exception.close()
        self.assertTrue(session["authenticated"])
        self.assertEqual(session["user"]["username"], "tester")

    def test_auth_registration_invitation_admin_and_removal_flow(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-user-lifecycle-{uuid.uuid4().hex}.sqlite"
        self._create_test_user(db_path)
        handler_class = type(
            "TestUFIDUserLifecycleRequestHandler",
            (UFIDRequestHandler,),
            {"db_path": db_path, "web_root": ROOT / "web"},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            admin_token = self._login(base_url)
            registered = self._post_json(
                f"{base_url}/api/v1/auth/register",
                {
                    "username": "self-register",
                    "password": "correct horse battery staple",
                },
            )
            with self.assertRaises(HTTPError) as inactive_login:
                self._post_json(
                    f"{base_url}/api/v1/auth/login",
                    {
                        "username": "self-register",
                        "password": "correct horse battery staple",
                    },
                )
            activated = self._post_json(
                f"{base_url}/api/v1/auth/users/{registered['user']['id']}/activate",
                {},
                token=admin_token,
            )
            self_registered_token = self._post_json(
                f"{base_url}/api/v1/auth/login",
                {
                    "username": "self-register",
                    "password": "correct horse battery staple",
                },
            )["token"]

            invited = self._post_json(
                f"{base_url}/api/v1/auth/users",
                {
                    "username": "invitee",
                    "display_name": "Invitee",
                    "roles": ["reader", "contributor"],
                },
                token=admin_token,
            )
            updated_invitee_roles = self._post_json(
                f"{base_url}/api/v1/auth/users/{invited['user']['id']}/roles",
                {"roles": ["reader", "curator"]},
                token=admin_token,
            )
            with self.assertRaises(HTTPError) as self_role_removal:
                self._post_json(
                    f"{base_url}/api/v1/auth/users/1/roles",
                    {"roles": ["reader"]},
                    token=admin_token,
                )
            registration = invited["registration"]
            validated = self._get_json(
                f"{base_url}/api/v1/auth/registration/validate?token={registration['token']}"
            )
            completed = self._post_json(
                f"{base_url}/api/v1/auth/registration/complete",
                {
                    "token": registration["token"],
                    "password": "invitee correct horse password",
                },
            )
            invitee_token = completed["token"]
            password_changed = self._post_json(
                f"{base_url}/api/v1/auth/me/password",
                {
                    "current_password": "invitee correct horse password",
                    "new_password": "invitee better horse password",
                },
                token=invitee_token,
            )
            removal = self._post_json(
                f"{base_url}/api/v1/auth/me/removal-request",
                {},
                token=invitee_token,
            )
            pending_removals = self._get_json(
                f"{base_url}/api/v1/auth/removal-requests",
                token=admin_token,
            )
            blocked = self._post_json(
                f"{base_url}/api/v1/auth/removal-requests/{removal['request']['id']}/block",
                {},
                token=admin_token,
            )
            users = self._get_json(f"{base_url}/api/v1/auth/users", token=admin_token)
            removee = self._post_json(
                f"{base_url}/api/v1/auth/users",
                {
                    "username": "removee",
                    "password": "removee correct horse password",
                    "roles": ["reader"],
                },
                token=admin_token,
            )
            removee_token = self._post_json(
                f"{base_url}/api/v1/auth/login",
                {
                    "username": "removee",
                    "password": "removee correct horse password",
                },
            )["token"]
            removee_request = self._post_json(
                f"{base_url}/api/v1/auth/me/removal-request",
                {},
                token=removee_token,
            )
            approved = self._post_json(
                f"{base_url}/api/v1/auth/removal-requests/{removee_request['request']['id']}/approve",
                {},
                token=admin_token,
            )
            with self.assertRaises(HTTPError) as removed_login:
                self._post_json(
                    f"{base_url}/api/v1/auth/login",
                    {
                        "username": "removee",
                        "password": "removee correct horse password",
                    },
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(inactive_login.exception.code, 401)
        inactive_login.exception.close()
        self.assertTrue(registered["requires_activation"])
        self.assertEqual(activated["user"]["status"], "active")
        self.assertTrue(self_registered_token)
        self.assertTrue(registration["completion_url"].startswith(base_url))
        self.assertEqual(updated_invitee_roles["user"]["roles"], ["curator", "reader"])
        self.assertEqual(self_role_removal.exception.code, 400)
        self_role_removal.exception.close()
        self.assertEqual(validated["registration"]["user"]["username"], "invitee")
        self.assertEqual(completed["user"]["username"], "invitee")
        self.assertTrue(password_changed["changed"])
        self.assertEqual(removal["request"]["status"], "pending")
        self.assertEqual(pending_removals["count"], 1)
        self.assertEqual(blocked["request"]["status"], "blocked")
        self.assertGreaterEqual(users["count"], 3)
        self.assertEqual(removee["user"]["status"], "active")
        self.assertEqual(approved["request"]["status"], "approved")
        self.assertEqual(removed_login.exception.code, 401)
        removed_login.exception.close()

    def test_local_automation_token_can_write_without_persisted_session(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-local-token-{uuid.uuid4().hex}.sqlite"
        handler_class = type(
            "TestUFIDLocalAutomationRequestHandler",
            (UFIDRequestHandler,),
            {
                "db_path": db_path,
                "web_root": ROOT / "web",
                "local_api_token": "local-secret-token",
            },
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            with self.assertRaises(HTTPError) as raised:
                self._post_json(
                    f"{base_url}/api/v1/files",
                    {
                        "display_name": "unauthorized.bin",
                        "size_bytes": 4,
                        "hashes": {
                            "crc32": "12345678",
                            "md5": "d" * 32,
                            "sha1": "e" * 40,
                        },
                    },
                )
            created = self._post_json(
                f"{base_url}/api/v1/files",
                {
                    "display_name": "local-token.bin",
                    "size_bytes": 4,
                    "hashes": {
                        "crc32": "12345678",
                        "md5": "d" * 32,
                        "sha1": "e" * 40,
                    },
                },
                token="local-secret-token",
            )
            loaded = self._get_json(
                f"{base_url}/api/v1/files/{created['id']}",
                token="local-secret-token",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(raised.exception.code, 401)
        raised.exception.close()
        self.assertTrue(created["created"])
        self.assertEqual(loaded["file"]["display_name"], "local-token.bin")

    def test_cli_add_and_lookup_can_use_local_server_token(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"server-cli-local-{uuid.uuid4().hex}.sqlite"
        sample_path = SCRATCH / f"server-cli-local-{uuid.uuid4().hex}.bin"
        sample_path.write_bytes(b"server backed cli sample")
        handler_class = type(
            "TestUFIDCliLocalRequestHandler",
            (UFIDRequestHandler,),
            {
                "db_path": db_path,
                "web_root": ROOT / "web",
                "local_api_token": "local-cli-token",
            },
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            with redirect_stdout(StringIO()):
                add_exit = add.main(
                    [
                        str(sample_path),
                        "--backend",
                        base_url,
                        "--api-token",
                        "local-cli-token",
                        "--json",
                    ]
                )
            lookup_output = StringIO()
            with redirect_stdout(lookup_output):
                lookup_exit = lookup.main(
                    [
                        str(sample_path),
                        "--backend",
                        base_url,
                        "--api-token",
                        "local-cli-token",
                        "--json",
                    ]
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        lookup_payload = json.loads(lookup_output.getvalue())
        self.assertEqual(add_exit, 0)
        self.assertEqual(lookup_exit, 0)
        self.assertTrue(lookup_payload[0]["found"])
        self.assertEqual(lookup_payload[0]["file"]["display_name"], sample_path.name)

    def _create_test_user(self, db_path: Path) -> None:
        with closing(connect(db_path)) as connection:
            create_user(
                connection,
                username="tester",
                password="correct horse battery staple",
                roles=["reader", "contributor", "admin"],
            )

    def _login(self, base_url: str) -> str:
        login = self._post_json(
            f"{base_url}/api/v1/auth/login",
            {"username": "tester", "password": "correct horse battery staple"},
        )
        return login["token"]

    def _get_json(self, url: str, token: str | None = None) -> dict:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(url, headers=headers, method="GET")
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post_json(self, url: str, payload: dict, token: str | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
