
from pathlib import Path

from auditor.risk_score import (
    calculate_risk_score,
    get_risk_category,
)


def print_audit_report(project_path, files, findings):
    separator = "=" * 60
    divider = "-" * 60

    score = calculate_risk_score(findings)
    category = get_risk_category(score)

    print("\n" + separator)
    print("STATIC CONFIGURATION RISK AUDITOR")
    print(separator)
    print(f"Project: {Path(project_path).name}")
    print(f"Configuration files: {len(files)}")

    print("\n" + separator)
    print("RISK SUMMARY")
    print(separator)
    print(f"Risk Score : {score:g}/100")
    print(f"Category   : {category}")
    print(f"Findings   : {len(findings)}")

    for index, finding in enumerate(findings, start=1):
        print("\n" + divider)
        print(f"Finding #{index}")
        print(f"Rule ID       : {finding.rule_id}")
        print(f"Title         : {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"File          : {finding.file}")
        print(f"Confidence    : {finding.confidence}")
        print(f"Evidence      : {finding.evidence}")
        print(f"Description   : {finding.description}")
        print(f"Recommendation: {finding.recommendation}")

    print("\n" + separator)
    print("AUDIT COMPLETED")
    print(separator)
