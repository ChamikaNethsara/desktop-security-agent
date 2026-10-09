from abc import ABC, abstractmethod

from results.findings import Finding


class BaseRule(ABC):
    rule_id = ""
    title = ""
    severity = "Medium"

    @abstractmethod
    def check(self, data, file_path):
        pass

    def finding(
        self,
        file_path,
        evidence,
        description,
        recommendation,
        line=0,
    ):
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            file=str(file_path),
            description=description,
            recommendation=recommendation,
            evidence=str(evidence)[:300],
            line=line,
        )