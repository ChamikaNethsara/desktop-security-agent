from dataclasses import asdict, dataclass


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    description: str
    recommendation: str
    evidence: str
    line: int = 0
    confidence: float = 1.0
    exposure: float = 1.0
    recurrence: float = 1.0

    def to_dict(self):
        return asdict(self)