from rules.base_rule import BaseRule


SENSITIVE_PORTS = {
    21, 22, 23, 25, 3306, 3389, 5432, 6379, 27017
}


class SensitivePortRule(BaseRule):
    rule_id = "CFG-003"
    title = "Sensitive port broadly exposed"
    severity = "High"

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
                parts = port_text.split(":")

                try:
                    container_port = int(parts[-1].split("/")[0])
                except ValueError:
                    continue

                broad = (
                    port_text.startswith("0.0.0.0:")
                    or port_text.startswith("[::]:")
                )

                if container_port in SENSITIVE_PORTS and broad:
                    findings.append(
                        self.finding(
                            file_path,
                            port_text,
                            f"Service '{service_name}' broadly exposes a sensitive port.",
                            "Restrict access using a private binding or firewall.",
                        )
                    )

        return findings