from __future__ import annotations

from pathlib import Path
import os
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.paths import default_user_data_dir
from ufid import api_client

SCRATCH = default_user_data_dir() / "test-runs"


class APIClientTests(unittest.TestCase):
    def test_session_store_is_keyed_by_backend_url(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        session_file = SCRATCH / f"sessions-{uuid.uuid4().hex}.json"
        previous = os.environ.get("UFID_SESSION_FILE")
        os.environ["UFID_SESSION_FILE"] = str(session_file)
        try:
            api_client.save_session(
                "https://ufid.example.test/",
                "secret-token",
                {"user": {"username": "alice"}, "expires_at": "later"},
            )
            loaded = api_client.load_session_token("https://ufid.example.test")
            api_client.clear_session("https://ufid.example.test")
            cleared = api_client.load_session_token("https://ufid.example.test")
        finally:
            if previous is None:
                os.environ.pop("UFID_SESSION_FILE", None)
            else:
                os.environ["UFID_SESSION_FILE"] = previous

        self.assertEqual(loaded, "secret-token")
        self.assertIsNone(cleared)


if __name__ == "__main__":
    unittest.main()
