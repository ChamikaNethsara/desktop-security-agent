from pathlib import Path

from app.paths import (
    APP_NAME,
    config_file_path,
    database_path,
    secrets_database_path,
    user_data_directory,
)


def test_user_data_directory_uses_local_app_data(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    result = user_data_directory()

    assert result == tmp_path / APP_NAME
    assert result.is_dir()


def test_database_paths_are_under_user_data_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert database_path() == tmp_path / APP_NAME / "security_agent.db"
    assert secrets_database_path() == tmp_path / APP_NAME / "adsa_secrets.db"


def test_config_file_is_copied_to_user_writable_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    resource_root = tmp_path / "resources"
    bundled_config = resource_root / "config" / "file_rules.yaml"
    bundled_config.parent.mkdir(parents=True)
    bundled_config.write_text("version: 1\nfile_scanning: {}\n", encoding="utf-8")

    result = config_file_path("file_rules.yaml", resource_root=resource_root)

    assert result == tmp_path / APP_NAME / "config" / "file_rules.yaml"
    assert result.read_text(encoding="utf-8") == bundled_config.read_text(encoding="utf-8")


def test_config_file_name_cannot_escape_config_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    try:
        config_file_path("../outside.yaml", resource_root=tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected path traversal filename to be rejected.")
