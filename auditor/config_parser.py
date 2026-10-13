import json
from pathlib import Path

import yaml


class ConfigParser:
    def parse(self, file_path):
        path = Path(file_path)
        filename = path.name.lower()

        if filename == "dockerfile":
            return self._parse_dockerfile(path)

        if path.suffix.lower() in {".yaml", ".yml"}:
            with path.open("r", encoding="utf-8") as file:
                return yaml.safe_load(file) or {}

        if path.suffix.lower() == ".json":
            with path.open("r", encoding="utf-8") as file:
                return json.load(file)

        raise ValueError(f"Unsupported file format: {path.name}")

    @staticmethod
    def _parse_dockerfile(path):
        with path.open("r", encoding="utf-8") as file:
            lines = file.readlines()

        return {
            "_type": "dockerfile",
            "_lines": lines,
        }