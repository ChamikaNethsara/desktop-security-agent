from pathlib import Path

from rules.base_rule import BaseRule


UNSAFE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "secrets.json",
    "config.secret.json",
    "docker-compose.override.yml",
}


class UnsafeLocationRule(BaseRule):
    rule_id = "CFG-009"
    title = "Potentially unsafe configuration filename"
    severity = "High"

    def check(self, data, file_path):
        filename = Path(file_path).name.lower()

        if filename not in UNSAFE_NAMES:
            return []

        return [
            self.finding(
                file_path,
                filename,
                "The filename may indicate sensitive configuration stored in an unsafe location.",
                "Check file contents and Git tracking; keep real secrets out of source control.",
            )
        ]