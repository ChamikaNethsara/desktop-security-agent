from pathlib import Path

from auditor.file_discovery import discover_files

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_discovers_supported_files():
    files = discover_files(PROJECT_ROOT / "test_configs")
    names = {path.name for path in files}

    assert "vulnerable.yaml" in names
    assert "vulnerable.json" in names
    assert "Dockerfile" in names