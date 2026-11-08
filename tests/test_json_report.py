"""json_report.py için testler."""

import json
from datetime import datetime, timezone

import pytest

from sefalet.models import ScanResult
from sefalet.reporting.json_report import default_filename, write_json


@pytest.fixture
def scan(lab_authorization):
    return ScanResult(target="şirket.com.tr", authorization=lab_authorization,
                      started_at=datetime(2026, 11, 8, 12, 0, 5, tzinfo=timezone.utc))


def test_default_filename_is_safe(scan):
    name = default_filename(scan, "json")
    assert name == f"sefalet__irket.com.tr_20261108-120005_{scan.scan_id[:8]}.json"
    assert "/" not in default_filename(scan.model_copy(update={"target": "../../etc"}), "json")


def test_same_second_scans_get_different_names(lab_authorization):
    started = datetime(2026, 11, 8, 12, 0, 5, tzinfo=timezone.utc)
    a = ScanResult(target="ornek.com", authorization=lab_authorization, started_at=started)
    b = ScanResult(target="ornek.com", authorization=lab_authorization, started_at=started)
    assert default_filename(a, "json") != default_filename(b, "json")


def test_write_json_creates_dirs_and_valid_file(scan, tmp_path):
    path = write_json(scan, tmp_path / "alt" / "rapor.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == "şirket.com.tr"
    assert data["schema_version"] == "1.0"
    assert list(tmp_path.joinpath("alt").glob(".tmp_*")) == []  # geçici dosya kalmadı


def test_write_json_overwrites(scan, tmp_path):
    path = tmp_path / "rapor.json"
    path.write_text("eski")
    write_json(scan, path)
    assert json.loads(path.read_text())["scan_id"] == scan.scan_id


def test_write_json_failure_leaves_no_temp_file(scan, tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("disk dolu")

    monkeypatch.setattr("sefalet.reporting.json_report.os.replace", fail)
    with pytest.raises(OSError, match="disk dolu"):
        write_json(scan, tmp_path / "rapor.json")
    assert list(tmp_path.iterdir()) == []
