from rules.base_rule import BaseRule


class ProductionDebugRule(BaseRule):
    rule_id = "CFG-005"
    title = "Debug mode enabled in production"
    severity = "Medium"

    def check(self, data, file_path):
        findings = []

        if not isinstance(data, dict):
            return findings

        environment = str(
            data.get("environment", data.get("env", ""))
        ).lower()

        if environment not in {"production", "prod"}:
            return findings

        if data.get("debug") is True:
            findings.append(
                self.finding(
                    file_path,
                    "debug: true",
                    "Debug mode is enabled in a production configuration.",
                    "Disable debug mode in production.",
                )
            )

        services = data.get("services", {})

        if isinstance(services, dict):
            for name, service in services.items():
                if not isinstance(service, dict):
                    continue

                if service.get("debug") is True:
                    findings.append(
                        self.finding(
                            file_path,
                            f"services.{name}.debug: true",
                            "A service enables debug mode in production.",
                            "Disable debug mode for production services.",
                        )
                    )

        return findings