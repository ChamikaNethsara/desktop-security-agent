from __future__ import annotations

import os
import shutil
from pathlib import Path

APP_NAME = "Desktop Security Agent"


def application_root() -> Path:
    """
    Return the root directory containing bundled, read-only application resources.

    In a source checkout this is the repository root. In a PyInstaller one-folder
    build, app/paths.py is collected under the bundle's internal directory, so
    this resolves to that directory.
    """
    return Path(__file__).resolve().parent.parent


def user_data_directory() -> Path:
    """Return the writable application data directory."""
    if os.environ.get("APP_ENV", "").lower() == "development":
        data_directory = application_root() / "data"
    else:
        local_app_data = os.environ.get("LOCALAPPDATA")

        if local_app_data:
            base_directory = Path(local_app_data)
        elif os.name == "nt":
            base_directory = Path.home() / "AppData" / "Local"
        else:
            base_directory = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))

        data_directory = base_directory / APP_NAME

    data_directory.mkdir(parents=True, exist_ok=True)
    return data_directory


def database_path() -> Path:
    """Return the primary SQLite findings database path."""
    return user_data_directory() / "security_agent.db"


def secrets_database_path() -> Path:
    """Return the Component 2 encrypted-secrets database path."""
    return user_data_directory() / "adsa_secrets.db"


def key_file_path() -> Path:
    """Return the fallback master-key path used when the OS keyring is unavailable."""
    return user_data_directory() / "keys" / "master.key"


def backup_directory() -> Path:
    """Return the directory for encrypted masking backups and their manifest."""
    return user_data_directory() / "backups"


def reports_directory() -> Path:
    """Return the per-user directory for generated reports."""
    directory = user_data_directory() / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def config_file_path(filename: str, *, resource_root: Path | None = None) -> Path:
    """
    Return a writable per-user copy of a bundled YAML configuration file.

    The bundled config remains a read-only default. GUI changes are written to
    LocalAppData so they continue to work when installed under Program Files.
    The default file is copied into the user's config directory on first use.
    """
    if Path(filename).name != filename:
        raise ValueError("Configuration filename must be a simple filename.")

    root = Path(resource_root).resolve() if resource_root is not None else application_root()
    bundled_file = root / "config" / filename
    user_config_dir = user_data_directory() / "config"
    user_config_dir.mkdir(parents=True, exist_ok=True)
    writable_file = user_config_dir / filename

    if not writable_file.exists() and bundled_file.is_file():
        shutil.copy2(bundled_file, writable_file)

    return writable_file
