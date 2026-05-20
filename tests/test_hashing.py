from __future__ import annotations

from io import BytesIO
from pathlib import Path
import hashlib
import sys
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.hashing import compute_file_hashes, compute_stream_hashes
from ufid.paths import default_user_data_dir

SCRATCH = default_user_data_dir() / "test-runs"


def load_blake3():
    try:
        from blake3 import blake3
    except ImportError:
        return None
    return blake3


class HashingTests(unittest.TestCase):
    def test_compute_file_hashes_streams_expected_algorithms(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        path = SCRATCH / "hashing-sample.bin"
        payload = b"UFID sample payload"
        path.write_bytes(payload)

        result = compute_file_hashes(path)

        self.assertEqual(result.size_bytes, len(payload))
        self.assertEqual(
            result.hashes["crc32"],
            f"{zlib.crc32(payload) & 0xffffffff:08x}",
        )
        self.assertEqual(result.hashes["md5"], hashlib.md5(payload).hexdigest())
        self.assertEqual(result.hashes["sha1"], hashlib.sha1(payload).hexdigest())
        self.assertNotIn("sha256", result.hashes)
        self.assertNotIn("blake3", result.hashes)

    def test_optional_hashes_are_computed_when_requested(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        path = SCRATCH / "optional-hashing-sample.bin"
        payload = b"UFID optional payload"
        path.write_bytes(payload)

        algorithms = ["sha256"]
        blake3 = load_blake3()
        if blake3 is not None:
            algorithms.append("blake3")

        result = compute_file_hashes(path, algorithms=algorithms)

        self.assertEqual(result.hashes["sha256"], hashlib.sha256(payload).hexdigest())
        if blake3 is not None:
            self.assertEqual(result.hashes["blake3"], blake3(payload).hexdigest())

    def test_stream_hashing_rejects_invalid_runtime_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one hash algorithm"):
            compute_stream_hashes(BytesIO(b"payload"), algorithms=[])
        with self.assertRaisesRegex(ValueError, "chunk_size"):
            compute_stream_hashes(BytesIO(b"payload"), chunk_size=0)
        with self.assertRaisesRegex(ValueError, "Unsupported hash algorithm"):
            compute_stream_hashes(BytesIO(b"payload"), algorithms=["sha512"])


if __name__ == "__main__":
    unittest.main()
