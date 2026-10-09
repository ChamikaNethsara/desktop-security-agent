from fnmatch import fnmatch
from pathlib import Path

from config.rule_loader import RuleLoader


def discover_files(project_path):
    root = Path(project_path).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Expected a directory: {root}")

    config_path = (
        Path(__file__).resolve().parent.parent
        / "config"
        / "file_rules.yaml"
    )

    config = RuleLoader(config_path).load_file_rules()

    extensions = config.included_extensions
    filenames = config.included_filenames
    name_patterns = config.included_name_patterns
    excluded = config.excluded_directories

    discovered = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(root)

        if any(
            part.casefold() in excluded
            for part in relative.parts[:-1]
        ):
            continue

        filename = path.name.casefold()

        if (
            path.suffix.casefold() in extensions
            or filename in filenames
            or any(
                fnmatch(filename, pattern)
                for pattern in name_patterns
            )
        ):
            discovered.append(path)

    return sorted(discovered)