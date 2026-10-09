from config.default_config import WEAK_CREDENTIALS
from rules.base_rule import BaseRule


CREDENTIAL_KEYS = {
    "username",
    "user",
    "admin_username",
    "password",
    "passwd",
    "admin_password",
}


class WeakCredentialsRule(BaseRule):
    rule_id = "CFG-007"
    title = "Weak or default credentials"
    severity = "Critical"

    def check(self, data, file_path):
        findings = []

        def inspect(value, path="root"):
            if isinstance(value, dict):
                for key, child in value.items():
                    current_path = f"{path}.{key}"

                    if (
                        key.lower() in CREDENTIAL_KEYS
                        and isinstance(child, str)
                        and child.lower() in WEAK_CREDENTIALS
                    ):
                        findings.append(
                            self.finding(
                                file_path,
                                f"{current_path}: [REDACTED]",
                                "A configuration value uses a weak or default credential.",
                                "Use a strong unique credential and store secrets securely.",
                            )
                        )

                    inspect(child, current_path)

            elif isinstance(value, list):
                for index, child in enumerate(value):
                    inspect(child, f"{path}[{index}]")

        inspect(data)

        return findings