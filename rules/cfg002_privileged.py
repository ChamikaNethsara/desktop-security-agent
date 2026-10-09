from rules.base_rule import BaseRule


class PrivilegedContainerRule(BaseRule):
    rule_id = "CFG-002"
    title = "Privileged container execution"
    severity = "Critical"

    def check(self, data, file_path):
        findings = []

        if not isinstance(data, dict):
            return findings

        services = data.get("services", {})

        if isinstance(services, dict):
            for name, service in services.items():
                if (
                    isinstance(service, dict)
                    and service.get("privileged") is True
                ):
                    findings.append(
                        self.finding(
                            file_path,
                            f"services.{name}.privileged: true",
                            "A container is configured to run in privileged mode.",
                            "Disable privileged mode unless strictly necessary.",
                        )
                    )

        return findings