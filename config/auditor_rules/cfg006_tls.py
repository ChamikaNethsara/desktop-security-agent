from config.auditor_rules.base_rule import BaseRule


TLS_KEYS = {
    "verify_ssl",
    "verify_tls",
    "tls_verify",
    "ssl_verify",
    "certificate_verify",
    "verify_certificate",
}


class DisabledTlsRule(BaseRule):
    rule_id = "CFG-006"
    title = "TLS verification disabled"
    severity = "High"

    def check(self, data, file_path):
        findings = []

        def inspect(value, path="root"):
            if isinstance(value, dict):
                for key, child in value.items():
                    current_path = f"{path}.{key}"

                    if (
                        key.lower() in TLS_KEYS
                        and child is False
                    ):
                        findings.append(
                            self.finding(
                                file_path,
                                f"{current_path}: false",
                                "TLS or certificate verification is disabled.",
                                "Enable certificate verification and use trusted certificates.",
                            )
                        )

                    inspect(child, current_path)

            elif isinstance(value, list):
                for index, child in enumerate(value):
                    inspect(child, f"{path}[{index}]")

        inspect(data)

        return findings