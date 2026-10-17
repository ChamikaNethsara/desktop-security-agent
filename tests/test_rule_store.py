import shutil
from pathlib import Path

import pytest

from config.rule_loader import RuleConfigurationError
from config.rule_store import RuleStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def store(tmp_path):
    pattern_path = tmp_path / "pattern_rules.yaml"
    file_path = tmp_path / "file_rules.yaml"
    shutil.copy(PROJECT_ROOT / "config" / "pattern_rules.yaml", pattern_path)
    shutil.copy(PROJECT_ROOT / "config" / "file_rules.yaml", file_path)
    return RuleStore(pattern_path, file_path)


def custom_rule(**overrides):
    rule = {
        "pattern_id": "corp_token",
        "name": "Corp Token",
        "category": "api_key",
        "provider": "Corp",
        "regex": r"\bcorp_[A-Za-z0-9]{24}\b",
        "severity": "high",
        "base_confidence": 0.9,
        "entropy_required": False,
        "context_required": False,
        "enabled": True,
        "description": "internal",
    }
    rule.update(overrides)
    return rule


def by_id(store, pattern_id):
    return next(r for r in store.list_pattern_rules() if r["pattern_id"] == pattern_id)


def test_lists_builtin_and_custom_rules_with_full_details(store):
    rules = {r["pattern_id"]: r for r in store.list_pattern_rules()}
    assert rules["aws_access_key_id"]["regex"]          # built-in details are visible
    assert rules["aws_access_key_id"]["name"]
    assert rules["google_api_key"]["source"] == "custom"
    # a yaml entry that only repeats the built-in values is not a modification
    assert rules["private_key_pem"]["source"] == "built-in"


def test_add_edit_delete_custom_rule(store):
    store.save_pattern_rule(custom_rule())
    assert by_id(store, "corp_token")["source"] == "custom"

    store.save_pattern_rule(custom_rule(severity="critical", name="Renamed"), original_id="corp_token")
    edited = by_id(store, "corp_token")
    assert edited["severity"] == "critical" and edited["name"] == "Renamed"

    store.delete_pattern_rule("corp_token")
    assert all(r["pattern_id"] != "corp_token" for r in store.list_pattern_rules())


def test_duplicate_id_rejected(store):
    store.save_pattern_rule(custom_rule())
    with pytest.raises(RuleConfigurationError):
        store.save_pattern_rule(custom_rule())
    with pytest.raises(RuleConfigurationError):
        store.save_pattern_rule(custom_rule(pattern_id="aws_access_key_id"))


@pytest.mark.parametrize("bad", [
    {"regex": "("}, {"regex": ""}, {"base_confidence": 1.5}, {"base_confidence": "abc"},
    {"severity": "urgent"}, {"category": "nope"}, {"name": " "}, {"pattern_id": "has space"},
])
def test_invalid_rules_rejected_and_file_untouched(store, bad):
    before = store.pattern_rules_path.read_text(encoding="utf-8")
    with pytest.raises(RuleConfigurationError):
        store.save_pattern_rule(custom_rule(**bad))
    assert store.pattern_rules_path.read_text(encoding="utf-8") == before


def test_builtin_edit_is_minimal_override_and_reset(store):
    original = by_id(store, "aws_access_key_id")
    changed = dict(original, severity="low", enabled=False)
    store.save_pattern_rule(changed, original_id="aws_access_key_id")
    updated = by_id(store, "aws_access_key_id")
    assert updated["source"] == "modified"
    assert updated["severity"] == "low" and updated["enabled"] is False
    assert updated["regex"] == original["regex"]

    store.delete_pattern_rule("aws_access_key_id")   # reset to default
    reset = by_id(store, "aws_access_key_id")
    assert reset["source"] == "built-in"
    assert reset["enabled"] is True


def test_toggle_enabled(store):
    store.set_pattern_enabled("google_api_key", False)
    assert by_id(store, "google_api_key")["enabled"] is False
    store.set_pattern_enabled("google_api_key", True)
    assert by_id(store, "google_api_key")["enabled"] is True


def test_file_rules_roundtrip_and_validation(store):
    rules = store.read_file_rules()
    assert ".env" in rules["included_filenames"]
    rules["included_extensions"].append(".tf")
    rules["excluded_directories"].remove(".idea")
    store.save_file_rules(rules)
    again = store.read_file_rules()
    assert ".tf" in again["included_extensions"]
    assert ".idea" not in again["excluded_directories"]

    rules["included_filenames"].append("  ")
    with pytest.raises(RuleConfigurationError):
        store.save_file_rules(rules)


def test_file_rules_deduplicate_case_insensitively(store):
    rules = store.read_file_rules()
    rules["included_extensions"] += [".JSON", ".json"]
    store.save_file_rules(rules)
    exts = [e.casefold() for e in store.read_file_rules()["included_extensions"]]
    assert exts.count(".json") == 1
