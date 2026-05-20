from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
import hashlib
from typing import BinaryIO, Iterable
import zlib


REQUIRED_ALGORITHMS = ("crc32", "md5", "sha1")
OPTIONAL_ALGORITHMS = ("sha256", "blake3")
SUPPORTED_ALGORITHMS = REQUIRED_ALGORITHMS + OPTIONAL_ALGORITHMS
DEFAULT_ALGORITHMS = REQUIRED_ALGORITHMS
CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class HashResult:
    path: Path
    size_bytes: int
    hashes: dict[str, str]


def available_algorithms() -> tuple[str, ...]:
    return SUPPORTED_ALGORITHMS


def _new_hasher(algorithm: str):
    normalized = algorithm.lower()
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    if normalized == "crc32":
        return CRC32Hasher()
    if normalized == "blake3":
        try:
            from blake3 import blake3
        except ImportError as exc:
            raise RuntimeError(
                "BLAKE3 support requires the 'blake3' Python package. "
                "Install project dependencies before hashing with blake3."
            ) from exc
        return blake3()
    if normalized in {"md5", "sha1", "sha256"}:
        return hashlib.new(normalized)
    raise ValueError(f"Unsupported hash algorithm: {algorithm}")


class CRC32Hasher:
    def __init__(self) -> None:
        self._value = 0

    def update(self, chunk: bytes) -> None:
        self._value = zlib.crc32(chunk, self._value)

    def hexdigest(self) -> str:
        return f"{self._value & 0xffffffff:08x}"


def compute_file_hashes(
    path: str | Path,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    chunk_size: int = CHUNK_SIZE,
) -> HashResult:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Not a file: {file_path}")

    with file_path.open("rb") as file:
        size_bytes, hashes = compute_stream_hashes(
            file,
            algorithms=algorithms,
            chunk_size=chunk_size,
        )

    return HashResult(
        path=file_path,
        size_bytes=size_bytes,
        hashes=hashes,
    )


def compute_bytes_hashes(
    payload: bytes,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
) -> tuple[int, dict[str, str]]:
    return compute_stream_hashes(BytesIO(payload), algorithms=algorithms)


def compute_stream_hashes(
    stream: BinaryIO,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    chunk_size: int = CHUNK_SIZE,
) -> tuple[int, dict[str, str]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    normalized_algorithms = tuple(dict.fromkeys(name.lower() for name in algorithms))
    if not normalized_algorithms:
        raise ValueError("at least one hash algorithm is required")
    hashers = {name: _new_hasher(name) for name in normalized_algorithms}
    size_bytes = 0

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        size_bytes += len(chunk)
        for hasher in hashers.values():
            hasher.update(chunk)

    return size_bytes, {name: hasher.hexdigest() for name, hasher in hashers.items()}


def iter_input_files(path: str | Path, recursive: bool = True) -> list[Path]:
    input_path = Path(path)
    if input_path.is_file():
        return [input_path]
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input does not exist: {input_path}")

    iterator = input_path.rglob("*") if recursive else input_path.glob("*")
    return sorted(candidate for candidate in iterator if candidate.is_file())


def compute_path_hashes(
    path: str | Path,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    recursive: bool = True,
) -> list[HashResult]:
    return [
        compute_file_hashes(file_path, algorithms=algorithms)
        for file_path in iter_input_files(path, recursive=recursive)
    ]
