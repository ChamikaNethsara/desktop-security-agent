from pathlib import Path

from auditor.config_parser import ConfigParser

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_CONFIGS = PROJECT_ROOT / "test_configs"


def test_parse_yaml():
    parser = ConfigParser()
    data = parser.parse(TEST_CONFIGS / "vulnerable" / "vulnerable.yaml")

    assert data["environment"] == "production"


def test_parse_json():
    parser = ConfigParser()
    data = parser.parse(TEST_CONFIGS / "vulnerable" / "vulnerable.json")

    assert data["debug"] is True


def test_parse_dockerfile():
    parser = ConfigParser()
    data = parser.parse(TEST_CONFIGS / "vulnerable" / "Dockerfile")

    assert data["_type"] == "dockerfile"
    assert len(data["_lines"]) > 0