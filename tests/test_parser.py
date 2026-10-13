from auditor.config_parser import ConfigParser


def test_parse_yaml():
    parser = ConfigParser()
    data = parser.parse("test_configs/vulnerable/vulnerable.yaml")

    assert data["environment"] == "production"


def test_parse_json():
    parser = ConfigParser()
    data = parser.parse("test_configs/vulnerable/vulnerable.json")

    assert data["debug"] is True


def test_parse_dockerfile():
    parser = ConfigParser()
    data = parser.parse("test_configs/vulnerable/Dockerfile")

    assert data["_type"] == "dockerfile"
    assert len(data["_lines"]) > 0