import os
import stat

from config.auditor_rules.base_rule import BaseRule


class FilePermissionsRule(BaseRule):
    rule_id = "CFG-010"
    title = "World-writable configuration file"
    severity = "Medium"

    def check(self, data, file_path):

        # Unix permission bits do not reliably represent
        # Windows ACL permissions.
        if os.name == "nt":
            return []

        try:
            mode = os.stat(file_path).st_mode
        except OSError:
            return []

        if mode & stat.S_IWOTH:
            return [
                self.finding(
                    file_path,
                    oct(stat.S_IMODE(mode)),
                    "The file is writable by all local users.",
                    "Restrict file permissions to authorized users.",
                )
            ]

        return []