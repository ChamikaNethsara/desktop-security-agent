from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

from app.paths import build_report_path, default_report_filename, downloads_directory


def test_default_filename_is_timestamped_pdf():
    name = default_report_filename(datetime(2026, 10, 17, 10, 30, 5))
    assert name == "Security_Audit_Report_20261017_103005.pdf"


def test_downloads_directory_prefers_existing_downloads_folder(tmp_path):
    (tmp_path / "Downloads").mkdir()
    with mock.patch.object(Path, "home", return_value=tmp_path):
        assert downloads_directory() == tmp_path / "Downloads"


def test_downloads_directory_falls_back_to_home(tmp_path):
    with mock.patch.object(Path, "home", return_value=tmp_path):
        assert downloads_directory() == tmp_path


def test_build_report_path_adds_pdf_extension(tmp_path):
    assert build_report_path(str(tmp_path), "audit") == tmp_path / "audit.pdf"
    assert build_report_path(str(tmp_path), "audit.PDF") == tmp_path / "audit.PDF"


def test_build_report_path_accepts_folder_that_does_not_exist_yet(tmp_path):
    target = tmp_path / "new" / "reports"
    assert build_report_path(str(target), "a.pdf") == target / "a.pdf"


@pytest.mark.parametrize("folder,name", [
    ("", "a.pdf"), ("  ", "a.pdf"), ("C:/x", ""), ("C:/x", "  "),
    ("C:/x", "bad/name.pdf"), ("C:/x", "bad:name.pdf"), ("C:/x", "a*b.pdf"), ("C:/x", "..."),
])
def test_build_report_path_rejects_invalid_input(folder, name):
    with pytest.raises(ValueError):
        build_report_path(folder, name)


def test_build_report_path_rejects_file_as_folder(tmp_path):
    a_file = tmp_path / "file.txt"
    a_file.write_text("x")
    with pytest.raises(ValueError):
        build_report_path(str(a_file), "a.pdf")
