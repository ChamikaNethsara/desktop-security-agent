from auditor.auditor import ConfigurationAuditor


def test_vulnerable_configuration_generates_findings():
    auditor = ConfigurationAuditor()
    findings = auditor.audit_project("test_configs/vulnerable")

    rule_ids = {finding.rule_id for finding in findings}

    assert "CFG-001" in rule_ids
    assert "CFG-002" in rule_ids
    assert "CFG-004" in rule_ids
    assert "CFG-006" in rule_ids
    assert "CFG-007" in rule_ids


def test_all_ten_rules_are_registered():
    from auditor.rule_engine import RuleEngine

    engine = RuleEngine()

    assert len(engine.rules) == 10