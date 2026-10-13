from auditor.file_discovery import discover_files
from auditor.config_parser import ConfigParser
from auditor.rule_engine import RuleEngine


class ConfigurationAuditor:
    def __init__(self):
        self.parser = ConfigParser()
        self.engine = RuleEngine()

    def audit_file(self, file_path):
        findings = []

        try:
            data = self.parser.parse(file_path)
        except (ValueError, OSError, UnicodeError) as error:
            print(f"Could not parse {file_path}: {error}")
            return findings
        except Exception as error:
            # Includes malformed YAML/JSON parser errors.
            print(f"Could not parse {file_path}: {error}")
            return findings

        findings.extend(self.engine.run(data, file_path))

        return findings

    def audit_project(self, project_path):
        files = discover_files(project_path)
        findings = []

        for file_path in files:
            findings.extend(self.audit_file(file_path))

        return findings