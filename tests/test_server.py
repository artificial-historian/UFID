from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid
from contextlib import closing, redirect_stdout
from io import StringIO


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.server import UFIDRequestHandler, _coerce_metadata_payload
from ufid.database import connect, create_user
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
