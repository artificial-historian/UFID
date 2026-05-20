from __future__ import annotations

import argparse
import json
import os
import platform
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ufid import __version__
from ufid.archives import ARCHIVE_SUFFIXES, SINGLE_FILE_COMPRESSION_SUFFIXES
from ufid.paths import default_archive_tools_dir


USER_AGENT = f"UFID-Archive-Tool-Setup/{__version__}"
SEVENZIP_RELEASE_API = "https://api.github.com/repos/ip7z/7zip/releases/latest"
LIBARCHIVE_RELEASE_API = "https://api.github.com/repos/libarchive/libarchive/releases/latest"

BUILTIN_FORMATS = {
    "zip": [".zip", ".jar", ".war", ".ear", ".apk", ".xpi", ".crx"],
    "tar": [".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".txz", ".tar.xz"],
    "single_file_compression": [".gz", ".bz2", ".xz", ".lzma"],
}

EXTERNAL_FORMATS = [
    ".zipx",
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
    ".z",
    ".br",
]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    tools_dir = Path(args.tools_dir).resolve()
    bin_dir = tools_dir / "bin"
    manual_dir = tools_dir / "manual-install"
    downloads_dir = tools_dir / "downloads"

    if args.download:
        tools_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        manual_dir.mkdir(parents=True, exist_ok=True)
        downloads_dir.mkdir(parents=True, exist_ok=True)
        setup_results = download_and_setup(
            bin_dir=bin_dir,
            manual_dir=manual_dir,
            downloads_dir=downloads_dir,
            force=bool(args.force),
        )
        write_activation_scripts(tools_dir, bin_dir)
    else:
        setup_results = []

    report = build_report(bin_dir=bin_dir, setup_results=setup_results)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report, tools_dir=tools_dir, bin_dir=bin_dir, downloaded=args.download)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-archive-tools",
        description=(
            "Check UFID archive extractor coverage and optionally download "
            "portable external tools."
        ),
    )
    parser.add_argument(
        "--tools-dir",
        default=str(default_archive_tools_dir()),
        help="Directory for portable tools and manual-install downloads.",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download portable tools and manual-install packages.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download files even when cached files already exist.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON report.")
    return parser


def download_and_setup(
    *,
    bin_dir: Path,
    manual_dir: Path,
    downloads_dir: Path,
    force: bool,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        results.extend(setup_7zip(bin_dir, manual_dir, downloads_dir, force=force))
    except Exception as exc:
        results.append({"tool": "7zip", "status": "error", "message": str(exc)})

    try:
        results.extend(setup_libarchive_manual(manual_dir, force=force))
    except Exception as exc:
        results.append({"tool": "libarchive", "status": "error", "message": str(exc)})

    write_manual_readme(manual_dir)
    return results


def setup_7zip(
    bin_dir: Path,
    manual_dir: Path,
    downloads_dir: Path,
    *,
    force: bool,
) -> list[dict[str, Any]]:
    release = fetch_json(SEVENZIP_RELEASE_API)
    assets = release.get("assets") if isinstance(release, dict) else None
    if not isinstance(assets, list):
        raise RuntimeError("7-Zip release did not include downloadable assets")

    system = platform.system().lower()
    machine = normalize_machine(platform.machine())
    results: list[dict[str, Any]] = []

    if system == "windows":
        extra = select_asset(
            assets,
            lambda name: name.endswith("extra.7z"),
        )
        bootstrap = select_asset(
            assets,
            lambda name: name.endswith("7zr.exe"),
        )
        installer = select_asset(
            assets,
            lambda name: name.endswith(".exe") and machine in asset_machine_tags(name),
        )
        if installer is not None:
            results.append(
                download_asset(
                    installer,
                    manual_dir / installer["name"],
                    force=force,
                    status="manual",
                    message="7-Zip GUI installer downloaded for manual install fallback.",
                )
            )

        if extra is None or bootstrap is None:
            raise RuntimeError("7-Zip Windows portable assets were not found")
        bootstrap_path = downloads_dir / bootstrap["name"]
        results.append(download_asset(bootstrap, bootstrap_path, force=force))
        extra_path = downloads_dir / extra["name"]
        results.append(download_asset(extra, extra_path, force=force))

        extract_dir = downloads_dir.parent / "7zip"
        extract_dir.mkdir(parents=True, exist_ok=True)
        run_checked(
            [
                str(bootstrap_path),
                "x",
                str(extra_path),
                f"-o{extract_dir}",
                "-y",
            ],
            cwd=downloads_dir,
        )
        command_target = find_first(extract_dir, ("7za.exe", "7z.exe", "7zr.exe"))
        if command_target is None:
            raise RuntimeError("7-Zip extraction finished but no console executable was found")
        create_windows_launcher(bin_dir / "7z.cmd", command_target)
        create_windows_launcher(bin_dir / "7za.cmd", command_target)
        create_windows_launcher(bin_dir / "7zr.cmd", command_target)
        results.append(
            {
                "tool": "7zip",
                "status": "portable",
                "path": str(command_target),
                "message": "Portable 7-Zip console wrapper created.",
            }
        )
        return results

    if system in {"linux", "darwin"}:
        asset = select_7zip_posix_asset(assets, system=system, machine=machine)
        if asset is None:
            raise RuntimeError(f"No 7-Zip portable tar.xz asset for {system}/{machine}")
        archive_path = downloads_dir / asset["name"]
        results.append(download_asset(asset, archive_path, force=force))
        extract_dir = downloads_dir.parent / "7zip"
        extract_tar_xz(archive_path, extract_dir)
        command_target = find_first(extract_dir, ("7zz", "7z"))
        if command_target is None:
            raise RuntimeError("7-Zip extraction finished but no console executable was found")
        command_target.chmod(command_target.stat().st_mode | stat.S_IXUSR)
        launcher_name = "7zz" if command_target.name == "7zz" else "7z"
        create_posix_launcher(bin_dir / launcher_name, command_target)
        if launcher_name != "7z":
            create_posix_launcher(bin_dir / "7z", command_target)
        results.append(
            {
                "tool": "7zip",
                "status": "portable",
                "path": str(command_target),
                "message": "Portable 7-Zip console wrapper created.",
            }
        )
        return results

    raise RuntimeError(f"Unsupported platform for automatic 7-Zip setup: {platform.system()}")


def setup_libarchive_manual(manual_dir: Path, *, force: bool) -> list[dict[str, Any]]:
    release = fetch_json(LIBARCHIVE_RELEASE_API)
    tag = str(release.get("tag_name") or "latest") if isinstance(release, dict) else "latest"
    source_url = None
    if isinstance(release, dict):
        source_url = release.get("tarball_url") or release.get("zipball_url")
    if not isinstance(source_url, str) or not source_url:
        raise RuntimeError("libarchive release did not include a source archive URL")

    suffix = ".tar.gz" if "tarball" in source_url else ".zip"
    target = manual_dir / f"libarchive-{tag}-source{suffix}"
    return [
        download_url(
            source_url,
            target,
            force=force,
            tool="libarchive",
            status="manual",
            message=(
                "libarchive/bsdtar source downloaded. Build/install manually "
                "or install bsdtar through the OS package manager."
            ),
        )
    ]


def build_report(*, bin_dir: Path, setup_results: list[dict[str, Any]]) -> dict[str, Any]:
    local_env = os.environ.copy()
    local_env["PATH"] = str(bin_dir) + os.pathsep + local_env.get("PATH", "")
    current_archive_path = local_env.get("UFID_ARCHIVE_TOOL_PATH", "")
    local_env["UFID_ARCHIVE_TOOL_PATH"] = (
        str(bin_dir)
        if not current_archive_path
        else str(bin_dir) + os.pathsep + current_archive_path
    )
    tools = {
        "7zip": check_command(("7z", "7zz", "7za", "7zr"), env=local_env),
        "bsdtar": check_command(("bsdtar",), env=local_env),
    }
    zstandard_available = module_available("zstandard")
    external_available = any(item["available"] for item in tools.values())
    return {
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
        },
        "portable_bin": str(bin_dir),
        "setup_results": setup_results,
        "tools": tools,
        "supported_archives": {
            "builtin": BUILTIN_FORMATS,
            "optional_python": {
                "zstandard": {
                    "available": zstandard_available,
                    "suffixes": [".zst", ".tar.zst", ".tzst"] if zstandard_available else [],
                }
            },
            "external": {
                "available": external_available,
                "suffixes": EXTERNAL_FORMATS if external_available else [],
            },
            "recognized_suffixes": list(ARCHIVE_SUFFIXES),
            "single_file_compression_suffixes": list(SINGLE_FILE_COMPRESSION_SUFFIXES),
        },
    }


def print_report(
    report: dict[str, Any],
    *,
    tools_dir: Path,
    bin_dir: Path,
    downloaded: bool,
) -> None:
    print("UFID archive extractor report")
    print("=============================")
    platform_info = report["platform"]
    print(f"Platform: {platform_info['system']} {platform_info['machine']}")
    print(f"Portable tools directory: {tools_dir}")
    print(f"Portable bin directory:   {bin_dir}")
    print()

    if downloaded:
        print("Setup actions:")
        for item in report["setup_results"]:
            status = item.get("status", "unknown")
            tool = item.get("tool", "tool")
            message = item.get("message", "")
            path = item.get("path") or item.get("target")
            suffix = f" -> {path}" if path else ""
            print(f"  [{status}] {tool}: {message}{suffix}")
        print()

    print("External tools:")
    for name, info in report["tools"].items():
        if info["available"]:
            print(f"  ok      {name}: {info['command']} ({info.get('version') or 'version unknown'})")
        else:
            print(f"  missing {name}")
    print()

    supported = report["supported_archives"]
    print("Active built-in support:")
    for group, suffixes in supported["builtin"].items():
        print(f"  {group}: {', '.join(suffixes)}")

    zstd = supported["optional_python"]["zstandard"]
    print()
    if zstd["available"]:
        print("Optional Python support: zstandard active (.zst, .tar.zst, .tzst)")
    else:
        print("Optional Python support: zstandard missing")

    print()
    if supported["external"]["available"]:
        print("External extractor coverage active for:")
        print("  " + ", ".join(supported["external"]["suffixes"]))
    else:
        print("External extractor coverage inactive until 7-Zip or bsdtar is available.")

    print()
    print("To use portable tools with UFID:")
    if os.name == "nt":
        print(f"  $env:UFID_ARCHIVE_TOOL_PATH = '{bin_dir}'")
        print(f"  . '{tools_dir / 'activate-archive-tools.ps1'}'")
    else:
        print(f"  export UFID_ARCHIVE_TOOL_PATH='{bin_dir}'")
        print(f"  . '{tools_dir / 'activate-archive-tools.sh'}'")


def check_command(commands: tuple[str, ...], *, env: dict[str, str]) -> dict[str, Any]:
    for command in commands:
        found = shutil.which(command, path=env.get("PATH"))
        if found:
            return {
                "available": True,
                "command": command,
                "path": found,
                "version": command_version(found, env=env),
            }
    return {"available": False, "command": commands[0], "path": None, "version": None}


def command_version(command: str, *, env: dict[str, str]) -> str | None:
    attempts = ([command, "i"], [command, "--version"])
    for args in attempts:
        try:
            completed = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = completed.stdout.strip()
        if completed.returncode == 0 and text:
            first_line = text.splitlines()[0].strip()
            if first_line.lower().startswith("command line error"):
                continue
            return text.splitlines()[0].strip()
    return None


def fetch_json(url: str) -> Any:
    raw = fetch_bytes(url)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"downloaded invalid JSON from {url}") from exc


def fetch_bytes(url: str) -> bytes:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json, application/json;q=0.9, */*;q=0.1",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            return response.read()
    except HTTPError as exc:
        raise RuntimeError(f"download failed ({exc.code}) for {url}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"download failed for {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError(f"download timed out for {url}") from exc


def select_asset(assets: list[Any], predicate) -> dict[str, Any] | None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "").lower()
        if predicate(name) and asset.get("browser_download_url"):
            return asset
    return None


def select_7zip_posix_asset(
    assets: list[Any],
    *,
    system: str,
    machine: str,
) -> dict[str, Any] | None:
    if system == "darwin":
        return select_asset(
            assets,
            lambda name: name.endswith(".tar.xz") and "mac" in name,
        )
    if machine == "x64":
        token = "linux-x64"
    elif machine == "arm64":
        token = "linux-arm64"
    elif machine == "x86":
        token = "linux-x86"
    else:
        token = "linux-arm"
    return select_asset(
        assets,
        lambda name: name.endswith(".tar.xz") and token in name,
    )


def asset_machine_tags(name: str) -> set[str]:
    tags: set[str] = set()
    if "x64" in name:
        tags.add("x64")
    if "arm64" in name:
        tags.add("arm64")
    if "x86" in name:
        tags.add("x86")
    return tags


def download_asset(
    asset: dict[str, Any],
    target: Path,
    *,
    force: bool,
    status: str = "downloaded",
    message: str = "Downloaded.",
) -> dict[str, Any]:
    url = str(asset["browser_download_url"])
    return download_url(
        url,
        target,
        force=force,
        tool=str(asset.get("name") or target.name),
        status=status,
        message=message,
    )


def download_url(
    url: str,
    target: Path,
    *,
    force: bool,
    tool: str,
    status: str,
    message: str,
) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not force:
        return {
            "tool": tool,
            "status": "cached",
            "target": str(target),
            "message": "Using existing downloaded file.",
        }

    temp_path: Path | None = None
    try:
        payload = fetch_bytes(url)
        with tempfile.NamedTemporaryFile(delete=False, dir=str(target.parent)) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(payload)
        temp_path.replace(target)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise
    return {"tool": tool, "status": status, "target": str(target), "message": message}


def extract_tar_xz(archive_path: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, mode="r:xz") as archive:
        archive.extractall(target_dir, filter="data")


def run_checked(args: list[str], *, cwd: Path) -> None:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"command timed out after {exc.timeout} seconds: {' '.join(args)}") from exc
    except OSError as exc:
        raise RuntimeError(f"could not run command {' '.join(args)}: {exc}") from exc
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip() or f"command failed: {' '.join(args)}")


def find_first(root: Path, names: tuple[str, ...]) -> Path | None:
    expected = {name.lower() for name in names}
    for path in root.rglob("*"):
        if path.is_file() and path.name.lower() in expected:
            return path
    return None


def create_windows_launcher(path: Path, target: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'@echo off\r\n"{target}" %*\r\n',
        encoding="utf-8",
    )


def create_posix_launcher(path: Path, target: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'#!/bin/sh\nexec "{target}" "$@"\n',
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def write_activation_scripts(tools_dir: Path, bin_dir: Path) -> None:
    tools_dir.mkdir(parents=True, exist_ok=True)
    (tools_dir / "activate-archive-tools.ps1").write_text(
        (
            f"$env:UFID_ARCHIVE_TOOL_PATH = '{bin_dir}'\n"
            f"$env:PATH = '{bin_dir};' + $env:PATH\n"
            "Write-Host 'UFID archive tools activated.'\n"
        ),
        encoding="utf-8",
    )
    shell_script = tools_dir / "activate-archive-tools.sh"
    shell_script.write_text(
        (
            f"export UFID_ARCHIVE_TOOL_PATH='{bin_dir}'\n"
            f"export PATH='{bin_dir}':$PATH\n"
            "echo 'UFID archive tools activated.'\n"
        ),
        encoding="utf-8",
    )
    shell_script.chmod(shell_script.stat().st_mode | stat.S_IXUSR)


def write_manual_readme(manual_dir: Path) -> None:
    manual_dir.mkdir(parents=True, exist_ok=True)
    (manual_dir / "README.txt").write_text(
        (
            "UFID manual-install downloads\n"
            "============================\n\n"
            "Files in this directory could not be safely configured as portable "
            "tools by the setup script. Install or build them manually, then make "
            "their command-line tools available through PATH or "
            "UFID_ARCHIVE_TOOL_PATH.\n\n"
            "For libarchive, UFID uses the bsdtar command when it is available.\n"
        ),
        encoding="utf-8",
    )


def normalize_machine(machine: str) -> str:
    value = machine.lower()
    if value in {"amd64", "x86_64"}:
        return "x64"
    if value in {"i386", "i686", "x86"}:
        return "x86"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    return value


def module_available(name: str) -> bool:
    try:
        __import__(name)
    except ImportError:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
