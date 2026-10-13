import re

from config.auditor_rules.base_rule import BaseRule


SECRET_PATTERN = re.compile(
    r"^\s*(ENV|ARG)\s+"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"
    r"([A-Za-z0-9_-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_-]*)"
    r"\s*(?:=|\s)\s*(.+)$",
    re.IGNORECASE,
)


class DockerSecretsRule(BaseRule):
    rule_id = "CFG-004"
    title = "Potential hardcoded secret in Dockerfile"
    severity = "High"

    def check(self, data, file_path):
        findings = []

        if not isinstance(data, dict) or data.get("_type") != "dockerfile":
            return findings

        for line_number, line in enumerate(data["_lines"], start=1):
            match = SECRET_PATTERN.match(line.strip())

            if not match:
                continue

            value = match.group(3).strip().strip("'\"")

            if value.startswith("${") or value.startswith("$"):
                continue

            if not value or value.lower() in {"none", "null"}:
                continue

            findings.append(
                self.finding(
                    file_path,
                    f"{match.group(1)} {match.group(2)}=[REDACTED]",
                    "A Dockerfile ENV or ARG instruction may contain a hardcoded secret.",
                    "Supply secrets securely at runtime instead of embedding them in the image.",
                    line=line_number,
                )
            )

        return findings