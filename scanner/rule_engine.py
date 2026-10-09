from rules.cfg001_http import PlainHttpRule
from rules.cfg002_privileged import PrivilegedContainerRule
from rules.cfg003_ports import SensitivePortRule
from rules.cfg004_docker_secrets import DockerSecretsRule
from rules.cfg005_debug import ProductionDebugRule
from rules.cfg006_tls import DisabledTlsRule
from rules.cfg007_credentials import WeakCredentialsRule
from rules.cfg008_binding import BroadBindingRule
from rules.cfg009_unsafe_location import UnsafeLocationRule
from rules.cfg010_permissions import FilePermissionsRule


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