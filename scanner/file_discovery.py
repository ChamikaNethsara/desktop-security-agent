from pathlib import Path

from config.rule_loader import load_file_rules


def discover_files(project_path):
    root = Path(project_path).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Expected a directory: {root}")

    config = load_file_rules()

    extensions = set(config.get("supported_extensions", []))
    special_names = {
        name.lower()
        for name in config.get("special_filenames", [])
    }
    ignored = set(config.get("ignored_directories", []))

    discovered = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(root)

        if any(part in ignored for part in relative.parts[:-1]):
            continue

        if (
            path.suffix.lower() in extensions
            or path.name.lower() in special_names
        ):
            discovered.append(path)

    return sorted(discovered)