from auditor.file_discovery import discover_files


def test_discovers_supported_files():
    files = discover_files("test_configs")
    names = {path.name for path in files}

    assert "vulnerable.yaml" in names
    assert "vulnerable.json" in names
    assert "Dockerfile" in names