from __future__ import annotations

from contextlib import redirect_stdout
from importlib import resources
from io import StringIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid import __version__
from ufid import cli
from ufid import local_ia_discovery
from ufid.paths import default_archive_tools_dir, default_user_data_dir, resolve_web_root


class StandaloneToolTests(unittest.TestCase):
    def test_unified_cli_reports_release_version(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = cli.main(["--version"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(output.getvalue().strip(), f"ufid {__version__}")

    def test_default_web_root_resolves_for_source_or_packaged_install(self) -> None:
        web_root = resolve_web_root(None)

        self.assertTrue((web_root / "index.html").is_file())
        self.assertTrue((web_root / "app.js").is_file())
        self.assertTrue((web_root / "files.html").is_file())
        self.assertTrue((web_root / "files.js").is_file())
        self.assertTrue((web_root / "goldrush.html").is_file())
        self.assertTrue((web_root / "goldrush.js").is_file())
        self.assertTrue((web_root / "styles.css").is_file())

    def test_web_assets_are_packaged_under_ufid(self) -> None:
        package_root = resources.files("ufid.web")

        self.assertTrue(package_root.joinpath("index.html").is_file())
        self.assertTrue(package_root.joinpath("app.js").is_file())
        self.assertTrue(package_root.joinpath("files.html").is_file())
        self.assertTrue(package_root.joinpath("files.js").is_file())
        self.assertTrue(package_root.joinpath("goldrush.html").is_file())
        self.assertTrue(package_root.joinpath("goldrush.js").is_file())
        self.assertTrue(package_root.joinpath("styles.css").is_file())
        self.assertTrue(package_root.joinpath("assets", "ufid-mark.svg").is_file())

    def test_standalone_data_directories_are_user_scoped(self) -> None:
        data_dir = default_user_data_dir()
        tools_dir = default_archive_tools_dir()

        self.assertEqual(tools_dir.parent, data_dir)
        self.assertEqual(data_dir, Path("D:/UFID-data"))

    def test_local_ia_discovery_logs_metadata_mode_without_server(self) -> None:
        data_dir = default_user_data_dir() / "test-runs" / "local-ia-discovery-standalone"
        output = StringIO()

        def fake_ingest_main(argv: list[str]) -> int:
            self.assertIn("--mode", argv)
            self.assertIn("metadata", argv)
            self.assertEqual(argv[argv.index("--collection") + 1], "vintagesoftware")
            self.assertIn("--discover-collections", argv)
            self.assertIn("--collection-depth", argv)
            print("fake ingest ran")
            return 0

        with patch.object(local_ia_discovery.ia_ingest, "main", fake_ingest_main):
            with redirect_stdout(output):
                exit_code = local_ia_discovery.main(
                    [
                        "--no-server",
                        "--data-dir",
                        str(data_dir),
                        "--max-items",
                        "1",
                    ]
                )

        log_path = data_dir / "logs" / "ia-discovery.log"
        self.assertEqual(exit_code, 0)
        self.assertIn("Starting Internet Archive discovery mode", output.getvalue())
        self.assertIn("IA query:      collection:vintagesoftware", output.getvalue())
        self.assertIn("IA collections: discovery enabled", output.getvalue())
        self.assertIn("fake ingest ran", log_path.read_text(encoding="utf-8"))

    def test_local_ia_discovery_uses_local_server_backend_by_default(self) -> None:
        data_dir = default_user_data_dir() / "test-runs" / "local-ia-discovery-server-backed"
        output = StringIO()

        class FakeServer:
            def shutdown(self) -> None:
                pass

            def server_close(self) -> None:
                pass

        class FakeThread:
            def join(self, timeout: int) -> None:
                pass

        def fake_start_server(**kwargs):
            self.assertTrue(kwargs["local_api_token"])
            return FakeServer(), FakeThread(), 8999

        def fake_ingest_main(argv: list[str]) -> int:
            self.assertIn("--backend", argv)
            self.assertEqual(argv[argv.index("--backend") + 1], "http://127.0.0.1:8999")
            self.assertIn("--api-token", argv)
            self.assertNotIn("--db", argv)
            print("server-backed fake ingest ran")
            return 0

        with patch.object(local_ia_discovery, "start_server", fake_start_server):
            with patch.object(local_ia_discovery.ia_ingest, "main", fake_ingest_main):
                with redirect_stdout(output):
                    exit_code = local_ia_discovery.main(
                        [
                            "--data-dir",
                            str(data_dir),
                            "--max-items",
                            "1",
                        ]
                    )

        self.assertEqual(exit_code, 0)
        self.assertIn(
            "UFID server is healthy at http://127.0.0.1:8999",
            output.getvalue(),
        )
        self.assertIn("server-backed fake ingest ran", output.getvalue())


if __name__ == "__main__":
    unittest.main()
