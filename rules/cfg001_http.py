import re

from rules.base_rule import BaseRule


class PlainHttpRule(BaseRule):
    rule_id = "CFG-001"
    title = "Plain HTTP detected"
    severity = "High"

    def check(self, data, file_path):
        text = str(data)
        findings = []

        for match in re.finditer(r"http://[^\s'\"<>]+", text):
            findings.append(
                self.finding(
                    file_path,
                    match.group(),
                    "A configuration value contains a plain HTTP URL.",
                    "Use HTTPS when transmitting sensitive information.",
                )
            )

        return findings