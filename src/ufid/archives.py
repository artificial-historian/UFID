from __future__ import annotations

import bz2
from dataclasses import dataclass
import gzip
from io import BytesIO
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from typing import Iterable


@dataclass(frozen=True)
class ArchiveEntry:
    archive_path: str | None
    is_empty_directory: bool
    payload: bytes | None = None
    error: str | None = None


ARCHIVE_SUFFIXES = (
    ".zip",
    ".zipx",
    ".jar",
    ".war",
    ".ear",
    ".apk",
    ".xpi",
    ".crx",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tbz2",
    ".tar.bz2",
    ".txz",
    ".tar.xz",
    ".tzst",
    ".tar.zst",
    ".7z",
    ".rar",
    ".cab",
    ".arj",
    ".lha",
    ".lzh",
    ".cpio",
    ".rpm",
    ".deb",
    ".wim",
    ".swm",
    ".esd",
    ".chm",
    ".msi",
    ".nsis",
    ".iso",
    ".isz",
    ".udf",
    ".img",
    ".nrg",
    ".mdf",
    ".cdi",
    ".ccd",
    ".dmg",
    ".vhd",
    ".vhdx",
    ".chd",
    ".ecm",
    ".gz",
    ".bz2",
    ".xz",
    ".lzma",
    ".zst",
    ".z",
    ".br",
)
BUILTIN_ARCHIVE_SUFFIXES = (
    ".zip",
    ".zipx",
    ".jar",
    ".war",
    ".ear",
    ".apk",
    ".xpi",
    ".crx",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tbz2",
    ".tar.bz2",
    ".txz",
    ".tar.xz",
    ".tzst",
    ".tar.zst",
    ".gz",
    ".bz2",
    ".xz",
    ".lzma",
    ".zst",
    ".z",
    ".br",
)
NON_ARCHIVE_SUFFIXES = (
    ".cdx.gz",
    ".warc.gz",
)
COMPOUND_ARCHIVE_SUFFIXES = tuple(
    sorted((suffix for suffix in ARCHIVE_SUFFIXES if suffix.count(".") > 1), key=len, reverse=True)
)
SINGLE_FILE_COMPRESSION_SUFFIXES = (".gz", ".bz2", ".xz", ".lzma", ".zst", ".z", ".br")
EXTERNAL_LIST_TIMEOUT_SECONDS = 60
EXTERNAL_EXTRACT_TIMEOUT_SECONDS = 300


def looks_like_archive_path(path: str | Path | None) -> bool:
    if path is None:
        return False
    return _archive_suffix(str(path)) in ARCHIVE_SUFFIXES


def looks_like_supported_archive_path(path: str | Path | None) -> bool:
    if path is None:
        return False
    suffix = _archive_suffix(str(path))
    if suffix in BUILTIN_ARCHIVE_SUFFIXES:
        return True
    return looks_like_archive_path(path) and _external_extractor_available()


def looks_like_single_file_compression_path(path: str | Path | None) -> bool:
    if path is None:
        return False
    suffix = _archive_suffix(str(path))
    return suffix in SINGLE_FILE_COMPRESSION_SUFFIXES


def looks_like_supported_archive_container_path(path: str | Path | None) -> bool:
    if path is None:
        return False
    if looks_like_single_file_compression_path(path):
        return False
    return looks_like_supported_archive_path(path)


def is_supported_archive(path: str | Path) -> bool:
    file_path = Path(path)
    if _looks_like_non_archive_path(file_path):
        return False
    return (
        _is_zip_path(file_path)
        or _is_tar_path(file_path)
        or _is_single_compressed_path(file_path)
        or (looks_like_archive_path(file_path) and _external_extractor_available())
    )


def is_supported_archive_payload(payload: bytes) -> bool:
    return _is_zip_payload(payload) or _is_tar_payload(payload)


def iter_archive_entries(path: str | Path, name_hint: str | None = None) -> list[ArchiveEntry]:
    file_path = Path(path)
    if _looks_like_non_archive_path(file_path):
        return []

    if _is_zip_path(file_path):
        stdlib_entries: list[ArchiveEntry]
        try:
            with file_path.open("rb") as file:
                stdlib_entries = list(_iter_zip_entries(file))
        except OSError as exc:
            stdlib_entries = [_archive_error(None, f"Could not open archive: {_format_error(exc)}")]
        if not _entries_have_errors(stdlib_entries):
            return stdlib_entries
        external_entries = _iter_external_entries(file_path)
        if external_entries is not None:
            return external_entries
        return stdlib_entries

    if _is_tar_path(file_path):
        stdlib_entries = []
        try:
            with file_path.open("rb") as file:
                stdlib_entries = list(_iter_tar_entries(file))
        except OSError as exc:
            stdlib_entries = [_archive_error(None, f"Could not open archive: {_format_error(exc)}")]
        if not _entries_have_errors(stdlib_entries):
            return stdlib_entries
        external_entries = _iter_external_entries(file_path)
        if external_entries is not None:
            return external_entries
        return stdlib_entries

    if _is_single_compressed_path(file_path):
        entries = _iter_single_compressed_entries(file_path, name_hint=name_hint)
        if entries is not None:
            return entries

    if looks_like_archive_path(file_path):
        external_entries = _iter_external_entries(file_path)
        if external_entries is not None:
            return external_entries
        return [_no_extractor_error(file_path)]
    return []


def iter_archive_payload_entries(
    payload: bytes,
    name_hint: str | None = None,
) -> list[ArchiveEntry]:
    if _looks_like_non_archive_path(name_hint):
        return []
    if _is_zip_payload(payload):
        return list(_iter_zip_entries(BytesIO(payload)))
    if _is_tar_payload(payload):
        return list(_iter_tar_entries(BytesIO(payload)))
    if _looks_like_single_compressed_name(name_hint):
        entries = _iter_single_compressed_payload(payload, name_hint=name_hint)
        if entries is not None:
            return entries
    if name_hint and looks_like_archive_path(name_hint) and _external_extractor_available():
        return _iter_external_payload_entries(payload, name_hint=name_hint)
    return []


def _iter_zip_entries(source) -> Iterable[ArchiveEntry]:
    try:
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            directory_names = {
                _normalize_archive_path(info.filename)
                for info in infos
                if info.is_dir()
            }
            parent_directories = {
                parent
                for info in infos
                if not info.is_dir()
                for parent in _parent_directories(_normalize_archive_path(info.filename))
            }

            for directory in sorted(directory_names - parent_directories):
                yield ArchiveEntry(archive_path=directory, is_empty_directory=True)

            for info in infos:
                archive_path = _normalize_archive_path(info.filename)
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    yield _archive_error(
                        archive_path,
                        "Encrypted ZIP member cannot be read without a password",
                    )
                    continue
                try:
                    payload = archive.read(info)
                except RuntimeError as exc:
                    yield _archive_error(
                        archive_path,
                        f"Could not read ZIP member: {_format_error(exc)}",
                    )
                    continue
                except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                    yield _archive_error(
                        archive_path,
                        f"Could not read ZIP member: {_format_error(exc)}",
                    )
                    continue
                yield ArchiveEntry(
                    archive_path=archive_path,
                    is_empty_directory=False,
                    payload=payload,
                )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        yield _archive_error(None, f"Could not read ZIP archive: {_format_error(exc)}")


def _iter_tar_entries(source) -> Iterable[ArchiveEntry]:
    try:
        archive = tarfile.open(fileobj=source, mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        yield _archive_error(None, f"Could not read TAR archive: {_format_error(exc)}")
        return

    with archive:
        try:
            members = archive.getmembers()
        except (OSError, tarfile.TarError) as exc:
            yield _archive_error(
                None,
                f"Could not read TAR directory: {_format_error(exc)}",
            )
            return

        directory_names = {
            _normalize_archive_path(member.name)
            for member in members
            if member.isdir()
        }
        parent_directories = {
            parent
            for member in members
            if member.isfile()
            for parent in _parent_directories(_normalize_archive_path(member.name))
        }

        for directory in sorted(directory_names - parent_directories):
            yield ArchiveEntry(archive_path=directory, is_empty_directory=True)

        for member in members:
            archive_path = _normalize_archive_path(member.name)
            if not member.isfile():
                continue
            try:
                extracted = archive.extractfile(member)
                if extracted is None:
                    yield _archive_error(
                        archive_path,
                        "TAR member could not be extracted",
                    )
                    continue
                with extracted:
                    payload = extracted.read()
            except (OSError, tarfile.TarError, EOFError) as exc:
                yield _archive_error(
                    archive_path,
                    f"Could not read TAR member: {_format_error(exc)}",
                )
                continue

            yield ArchiveEntry(
                archive_path=archive_path,
                is_empty_directory=False,
                payload=payload,
            )


def _iter_single_compressed_entries(
    path: Path,
    *,
    name_hint: str | None = None,
) -> list[ArchiveEntry] | None:
    suffix = _single_compression_suffix(path.name)
    if suffix in {".zst", ".z", ".br"}:
        if suffix == ".zst":
            try:
                import zstandard
            except ImportError:
                return None
            try:
                with path.open("rb") as source:
                    payload = zstandard.ZstdDecompressor().decompress(source.read())
            except Exception as exc:
                return [_archive_error(None, f"Could not decompress Zstandard file: {_format_error(exc)}")]
            return [
                ArchiveEntry(
                    archive_path=_single_compressed_output_name(name_hint or path.name),
                    is_empty_directory=False,
                    payload=payload,
                )
            ]
        return None

    opener = {
        ".gz": gzip.open,
        ".bz2": bz2.open,
        ".xz": lzma.open,
        ".lzma": lzma.open,
    }.get(suffix)
    if opener is None:
        return None
    try:
        with opener(path, "rb") as source:
            payload = source.read()
    except (OSError, EOFError, lzma.LZMAError) as exc:
        return [_archive_error(None, f"Could not decompress file: {_format_error(exc)}")]
    return [
        ArchiveEntry(
            archive_path=_single_compressed_output_name(name_hint or path.name),
            is_empty_directory=False,
            payload=payload,
        )
    ]


def _iter_single_compressed_payload(
    payload: bytes,
    *,
    name_hint: str | None,
) -> list[ArchiveEntry] | None:
    suffix = _single_compression_suffix(name_hint or "")
    try:
        if suffix == ".gz":
            decompressed = gzip.decompress(payload)
        elif suffix == ".bz2":
            decompressed = bz2.decompress(payload)
        elif suffix in {".xz", ".lzma"}:
            decompressed = lzma.decompress(payload)
        elif suffix == ".zst":
            try:
                import zstandard
            except ImportError:
                return None
            decompressed = zstandard.ZstdDecompressor().decompress(payload)
        else:
            return None
    except Exception as exc:
        return [_archive_error(None, f"Could not decompress payload: {_format_error(exc)}")]
    return [
        ArchiveEntry(
            archive_path=_single_compressed_output_name(name_hint or "payload"),
            is_empty_directory=False,
            payload=decompressed,
        )
    ]


@dataclass(frozen=True)
class ExternalMember:
    path: str
    is_directory: bool
    encrypted: bool = False
    size: int | None = None


def _iter_external_payload_entries(payload: bytes, *, name_hint: str) -> list[ArchiveEntry]:
    suffix = _archive_suffix(name_hint) or Path(name_hint).suffix
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(payload)
            temp_path = Path(temp_file.name)
        return iter_archive_entries(temp_path, name_hint=name_hint)
    except OSError as exc:
        return [_archive_error(None, f"Could not stage nested archive payload: {_format_error(exc)}")]
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def _iter_external_entries(path: Path) -> list[ArchiveEntry] | None:
    backends = [_SevenZipBackend(), _BsdtarBackend()]
    errors: list[str] = []
    for backend in backends:
        if not backend.available():
            continue
        try:
            entries = backend.extract_entries(path)
        except ExternalExtractorError as exc:
            errors.append(str(exc))
            continue
        if entries:
            return entries
    if errors:
        return [_archive_error(None, "External archive extraction failed: " + " | ".join(errors))]
    return None


class ExternalExtractorError(RuntimeError):
    """Raised when an external archive extractor cannot list or extract content."""


class _SevenZipBackend:
    commands = ("7z", "7zz", "7za", "7zr")

    def __init__(self) -> None:
        self.executable = _first_available_command(self.commands)

    def available(self) -> bool:
        return self.executable is not None

    def extract_entries(self, path: Path) -> list[ArchiveEntry]:
        assert self.executable is not None
        listed = _run_command(
            [self.executable, "l", "-slt", "-bd", "-bb0", "--", str(path)],
            timeout=EXTERNAL_LIST_TIMEOUT_SECONDS,
        )
        members = _parse_7z_list_output(listed.stdout.decode("utf-8", errors="replace"))
        if not members:
            raise ExternalExtractorError("7z did not report extractable members")
        return _members_to_archive_entries(path, members, self._extract_member)

    def _extract_member(self, archive_path: Path, member: ExternalMember) -> bytes:
        assert self.executable is not None
        extracted = _run_command(
            [
                self.executable,
                "x",
                "-so",
                "-y",
                "-bd",
                "-bb0",
                "--",
                str(archive_path),
                member.path,
            ],
            timeout=EXTERNAL_EXTRACT_TIMEOUT_SECONDS,
            input_data=b"",
        )
        return extracted.stdout


class _BsdtarBackend:
    commands = ("bsdtar",)

    def __init__(self) -> None:
        self.executable = _first_available_command(self.commands)

    def available(self) -> bool:
        return self.executable is not None

    def extract_entries(self, path: Path) -> list[ArchiveEntry]:
        assert self.executable is not None
        listed = _run_command(
            [self.executable, "-tf", str(path)],
            timeout=EXTERNAL_LIST_TIMEOUT_SECONDS,
        )
        names = [
            line.strip()
            for line in listed.stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        if not names:
            raise ExternalExtractorError("bsdtar did not report extractable members")
        members = [
            ExternalMember(
                path=_normalize_archive_path(name),
                is_directory=name.endswith("/"),
            )
            for name in names
        ]
        return _members_to_archive_entries(path, members, self._extract_member)

    def _extract_member(self, archive_path: Path, member: ExternalMember) -> bytes:
        assert self.executable is not None
        extracted = _run_command(
            [self.executable, "-xOf", str(archive_path), member.path],
            timeout=EXTERNAL_EXTRACT_TIMEOUT_SECONDS,
        )
        return extracted.stdout


def _members_to_archive_entries(
    archive_path: Path,
    members: list[ExternalMember],
    extractor,
) -> list[ArchiveEntry]:
    directory_names = {
        _normalize_archive_path(member.path)
        for member in members
        if member.is_directory
    }
    parent_directories = {
        parent
        for member in members
        if not member.is_directory
        for parent in _parent_directories(_normalize_archive_path(member.path))
    }
    entries: list[ArchiveEntry] = [
        ArchiveEntry(archive_path=directory, is_empty_directory=True)
        for directory in sorted(directory_names - parent_directories)
    ]
    for member in members:
        archive_member_path = _normalize_archive_path(member.path)
        if member.is_directory:
            continue
        if member.encrypted:
            entries.append(
                _archive_error(
                    archive_member_path,
                    "Encrypted archive member cannot be read without a password",
                )
            )
            continue
        try:
            payload = extractor(archive_path, member)
        except ExternalExtractorError as exc:
            entries.append(_archive_error(archive_member_path, _format_error(exc)))
            continue
        if member.size is not None and len(payload) != member.size:
            entries.append(
                _archive_error(
                    archive_member_path,
                    f"Extracted size mismatch: expected {member.size}, got {len(payload)}",
                )
            )
            continue
        entries.append(
            ArchiveEntry(
                archive_path=archive_member_path,
                is_empty_directory=False,
                payload=payload,
            )
        )
    return entries


def _parse_7z_list_output(output: str) -> list[ExternalMember]:
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    in_entries = False
    for raw_line in output.splitlines():
        line = raw_line.strip("\ufeff")
        if line.strip("-") == "":
            if current:
                blocks.append(current)
                current = {}
            in_entries = True
            continue
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        current[key.strip()] = value.strip()
    if current:
        blocks.append(current)

    members: list[ExternalMember] = []
    for block in blocks:
        path = block.get("Path")
        if not path:
            continue
        if not in_entries and "Size" not in block and "Folder" not in block:
            continue
        if "Type" in block and "Physical Size" in block and "Size" not in block:
            continue
        is_directory = block.get("Folder") == "+" or block.get("Attributes", "").startswith("D")
        size = _optional_int(block.get("Size"))
        encrypted = block.get("Encrypted") == "+"
        if is_directory or size is not None:
            members.append(
                ExternalMember(
                    path=_normalize_archive_path(path),
                    is_directory=is_directory,
                    encrypted=encrypted,
                    size=size,
                )
            )
    return members


def _run_command(
    args: list[str],
    *,
    timeout: int,
    input_data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            args,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            creationflags=creationflags,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExternalExtractorError(_format_error(exc)) from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        message = stderr or stdout or f"exit code {completed.returncode}"
        raise ExternalExtractorError(message)
    return completed


def _archive_error(archive_path: str | None, error: str) -> ArchiveEntry:
    return ArchiveEntry(
        archive_path=archive_path,
        is_empty_directory=False,
        payload=None,
        error=error,
    )


def _no_extractor_error(path: Path) -> ArchiveEntry:
    return _archive_error(
        None,
        (
            "Archive looks supported but could not be opened with built-in readers; "
            "it may be corrupt, unsupported, or require an external extractor, "
            "and no external extractor was available. Install 7-Zip (7z/7zz/7za) "
            "or bsdtar/libarchive for broader archive and CD-image support."
        ),
    )


def _normalize_archive_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip("/")
    return normalized or path


def _parent_directories(path: str) -> set[str]:
    parts = [part for part in path.split("/") if part]
    return {"/".join(parts[:index]) for index in range(1, len(parts))}


def _is_zip_payload(payload: bytes) -> bool:
    try:
        return zipfile.is_zipfile(BytesIO(payload))
    except OSError:
        return False


def _is_tar_payload(payload: bytes) -> bool:
    try:
        with tarfile.open(fileobj=BytesIO(payload), mode="r:*"):
            return True
    except (OSError, tarfile.TarError):
        return False


def _is_zip_path(path: Path) -> bool:
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def _is_tar_path(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def _is_single_compressed_path(path: Path) -> bool:
    return _looks_like_single_compressed_name(path.name) and not _looks_like_tar_compressed(path.name)


def _looks_like_single_compressed_name(name: str | None) -> bool:
    if _looks_like_non_archive_path(name):
        return False
    return _single_compression_suffix(name or "") in SINGLE_FILE_COMPRESSION_SUFFIXES


def _looks_like_tar_compressed(name: str) -> bool:
    lower = name.lower()
    return lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tzst"))


def _single_compression_suffix(name: str) -> str:
    lower = name.lower()
    for suffix in SINGLE_FILE_COMPRESSION_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return ""


def _single_compressed_output_name(name: str) -> str:
    lower = name.lower()
    for suffix in SINGLE_FILE_COMPRESSION_SUFFIXES:
        if lower.endswith(suffix):
            stripped = name[: -len(suffix)]
            return Path(stripped).name or "decompressed"
    return Path(name).name or "decompressed"


def _entries_have_errors(entries: list[ArchiveEntry]) -> bool:
    return any(entry.error for entry in entries)


def _external_extractor_available() -> bool:
    return _first_available_command((*_SevenZipBackend.commands, *_BsdtarBackend.commands)) is not None


def _first_available_command(commands: tuple[str, ...]) -> str | None:
    for command in commands:
        found = shutil.which(command)
        if found:
            return found
    for directory in _configured_tool_dirs():
        for command in commands:
            for candidate in _command_candidates(directory, command):
                if candidate.is_file():
                    return str(candidate)
    return None


def _configured_tool_dirs() -> list[Path]:
    configured = os.environ.get("UFID_ARCHIVE_TOOL_PATH", "")
    return [
        Path(item)
        for item in configured.split(os.pathsep)
        if item.strip()
    ]


def _command_candidates(directory: Path, command: str) -> list[Path]:
    suffixes = ("",)
    if os.name == "nt":
        suffixes = ("", ".exe", ".cmd", ".bat")
    return [directory / f"{command}{suffix}" for suffix in suffixes]


def _archive_suffix(name: str) -> str:
    lower = name.lower()
    if _looks_like_non_archive_path(lower):
        return ""
    for suffix in COMPOUND_ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return Path(name).suffix


def _looks_like_non_archive_path(path: str | Path | None) -> bool:
    if path is None:
        return False
    return str(path).lower().endswith(NON_ARCHIVE_SUFFIXES)


def _optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _format_error(exc: BaseException) -> str:
    message = str(exc).strip()
    if not message:
        return exc.__class__.__name__
    return message
