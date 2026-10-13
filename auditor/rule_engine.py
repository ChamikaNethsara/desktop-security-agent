from config.auditor_rules.cfg001_http import PlainHttpRule
from config.auditor_rules.cfg002_privileged import PrivilegedContainerRule
from config.auditor_rules.cfg003_ports import SensitivePortRule
from config.auditor_rules.cfg004_docker_secrets import DockerSecretsRule
from config.auditor_rules.cfg005_debug import ProductionDebugRule
from config.auditor_rules.cfg006_tls import DisabledTlsRule
from config.auditor_rules.cfg007_credentials import WeakCredentialsRule
from config.auditor_rules.cfg008_binding import BroadBindingRule
from config.auditor_rules.cfg009_unsafe_location import UnsafeLocationRule
from config.auditor_rules.cfg010_permissions import FilePermissionsRule


class RuleEngine:
    def __init__(self):
        self.rules = [
            PlainHttpRule(),
            PrivilegedContainerRule(),
            SensitivePortRule(),
            DockerSecretsRule(),
            ProductionDebugRule(),
            DisabledTlsRule(),
            WeakCredentialsRule(),
            BroadBindingRule(),
            UnsafeLocationRule(),
            FilePermissionsRule(),
        ]

    def run(self, data, file_path):
        findings = []

        for rule in self.rules:
            findings.extend(rule.check(data, file_path))

        return findings