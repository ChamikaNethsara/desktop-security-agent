from rules.base_rule import BaseRule


class BroadBindingRule(BaseRule):
    rule_id = "CFG-008"
    title = "Broad host/network binding"
    severity = "Medium"

    def check(self, data, file_path):
        findings = []

        if not isinstance(data, dict):
            return findings

        services = data.get("services", {})

        if not isinstance(services, dict):
            return findings

        for service_name, service in services.items():
            if not isinstance(service, dict):
                continue

            for port in service.get("ports", []):
                port_text = str(port)

                if (
                    port_text.startswith("0.0.0.0:")
                    or port_text.startswith("[::]:")
                ):
                    findings.append(
                        self.finding(
                            file_path,
                            port_text,
                            f"Service '{service_name}' binds a port to all network interfaces.",
                            "Bind to a specific trusted interface where possible.",
                        )
                    )

        return findings