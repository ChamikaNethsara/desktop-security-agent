from pathlib import Path
import yaml

from app.paths import config_file_path


def discover_files(project_path):
    root = Path(project_path).resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise NotADirectoryError(root)
    rules_path = config_file_path("file_rules.yaml")
    config = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    scan = config.get('file_scanning', config)
    extensions = set(scan.get('included_extensions', scan.get('supported_extensions', [])))
    names = {n.lower() for n in scan.get('included_filenames', scan.get('special_filenames', []))}
    excluded = set(scan.get('excluded_directories', scan.get('ignored_directories', [])))
    return sorted(p for p in root.rglob('*') if p.is_file()
                  and not any(part in excluded for part in p.relative_to(root).parts[:-1])
                  and (p.suffix.lower() in extensions or p.name.lower() in names))
