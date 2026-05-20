from __future__ import annotations

from functools import lru_cache
from importlib import resources
import os
from pathlib import Path
import tomllib
from typing import Any


CONFIG_FILE_ENV = "UFID_CONFIG_FILE"
DATA_DIR_ENV = "UFID_DATA_DIR"
PROJECT_CONFIG_FILE = "ufid.config.toml"


def source_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_user_data_dir() -> Path:
    configured = os.environ.get(DATA_DIR_ENV)
    if configured:
        return _configured_path(configured)

    config_path, config = _load_config()
    configured = _config_value(config, "paths", "data_dir")
    if configured:
        return _configured_path(configured, base=config_path.parent if config_path else None)

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "UFID"
        return Path.home() / "AppData" / "Local" / "UFID"
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "ufid"
    return Path.home() / ".local" / "share" / "ufid"


def default_archive_tools_dir() -> Path:
    return default_user_data_dir() / "archive-extractors"


def default_sqlite_db_path() -> Path:
    return default_user_data_dir() / "ufid.sqlite"


def default_ia_state_db_path() -> Path:
    return default_user_data_dir() / "ia-ingest.sqlite"


def default_ia_cache_dir() -> Path:
    return default_user_data_dir() / "ia-cache"


def resolve_web_root(configured: str | Path | None = None) -> Path:
    if configured:
        return _validated_web_root(Path(configured).expanduser())

    env_web_root = os.environ.get("UFID_WEB_ROOT")
    if env_web_root:
        return _validated_web_root(Path(env_web_root).expanduser())

    for candidate in _web_root_candidates():
        if _is_web_root(candidate):
            return candidate.resolve()

    candidates = "\n  ".join(str(path) for path in _web_root_candidates())
    raise FileNotFoundError(
        "UFID web assets were not found. Pass --web-root or set UFID_WEB_ROOT. "
        f"Checked:\n  {candidates}"
    )


def _web_root_candidates() -> list[Path]:
    candidates = [source_root() / "web"]
    try:
        package_web = resources.files("ufid.web")
    except (ImportError, ModuleNotFoundError):
        package_web = None
    if package_web is not None:
        candidates.append(Path(str(package_web)))
    return candidates


@lru_cache(maxsize=1)
def _load_config() -> tuple[Path | None, dict[str, Any]]:
    path = _config_path()
    if path is None:
        return None, {}
    try:
        with path.open("rb") as file:
            payload = tomllib.load(file)
    except OSError as exc:
        raise RuntimeError(f"Could not read UFID config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"Could not parse UFID config file {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"UFID config file {path} must contain a TOML object")
    return path, payload


def _config_path() -> Path | None:
    configured = os.environ.get(CONFIG_FILE_ENV)
    if configured:
        path = _configured_path(configured)
        if not path.is_file():
            raise RuntimeError(f"UFID config file does not exist: {path}")
        return path

    candidate = source_root() / PROJECT_CONFIG_FILE
    return candidate if candidate.is_file() else None


def _config_value(config: dict[str, Any], section: str, key: str) -> str | None:
    table = config.get(section)
    if not isinstance(table, dict):
        return None
    value = table.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _configured_path(value: object, *, base: Path | None = None) -> Path:
    text = os.path.expandvars(str(value))
    path = Path(text).expanduser()
    if not path.is_absolute() and base is not None:
        path = base / path
    return path


def _validated_web_root(path: Path) -> Path:
    resolved = path.resolve()
    if not _is_web_root(resolved):
        raise FileNotFoundError(f"UFID web root does not exist or is incomplete: {resolved}")
    return resolved


def _is_web_root(path: Path) -> bool:
    return (
        path.is_dir()
        and (path / "index.html").is_file()
        and (path / "app.js").is_file()
        and (path / "styles.css").is_file()
    )
