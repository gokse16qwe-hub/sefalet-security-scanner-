"""pdf_report.py için testler.

Üretilen PDF'i pypdf ile açıp metnini okuyoruz. Böylece hem dosyanın
geçerli olduğunu hem de Türkçe karakterlerin doğru gömüldüğünü doğrularız.
"""

import pytest
from pypdf import PdfReader

from sefalet.models import (
    AuthorizationInfo,
    AuthorizationMethod,
    CheckResult,
    CheckStatus,
    Confidence,
    ScanResult,
    Severity,
)
from sefalet.reporting.pdf_report import write_pdf
from sefalet.risk import apply_risk


def pdf_text(path):
    return "\n".join(page.extract_text() for page in PdfReader(path).pages)


@pytest.fixture
def full_scan(make_finding):
    tls = CheckResult(
        check_name="tls", status=CheckStatus.COMPLETED,
        findings=[make_finding(id="TLS-001", title="Sertifikanın süresi dolmuş",
                               severity=Severity.HIGH, evidence="Bitiş: 2026-01-01")],
        details={"issuer": "Örnek Güvenilir CA", "days_left": -3,
                 "not_after": "2026-01-01T09:30:00+00:00", "protocol": "TLSv1.3",
                 "legacy_protocols": {"TLSv1": "test edilemedi"}},
    )
    headers = CheckResult(
        check_name="headers", status=CheckStatus.COMPLETED,
        findings=[make_finding(id="HDR-014", title="HttpOnly bayrağı olmayan çerezler",
                               severity=Severity.LOW, confidence=Confidence.PROBABLE,
                               evidence="Çerez: <script>alert('ş')</script> & oturum",
                               description="Şifreleme ğüşıöç İİ", recommendation="Düzeltin.",
                               references=["https://owasp.org/"])],
    )
    dns = CheckResult(check_name="dns", status=CheckStatus.ERROR, message="DNS sunucusu yanıt vermedi.",
                      details={"dnssec": None, "mx": []})
    ports = CheckResult(check_name="ports", status=CheckStatus.SKIPPED,
                        message="Port kontrolü varsayılan olarak kapalıdır.")
    auth = AuthorizationInfo(method=AuthorizationMethod.DECLARATION, details="Beyan eden: Ayşe Yılmaz")
    return apply_risk(ScanResult(target="şirket.com.tr", target_ips=["93.184.216.34"],
                                 authorization=auth, checks=[tls, headers, dns, ports]))


def test_pdf_contains_all_sections_and_turkish_text(full_scan, tmp_path):
    path = write_pdf(full_scan, tmp_path / "rapor.pdf")
    assert path.read_bytes().startswith(b"%PDF")
    text = pdf_text(path)
    for expected in [
        "Güvenlik Yapılandırma Raporu", "şirket.com.tr", "Yönetici Özeti", "Kapsam ve Yöntem",
        "Bulgu Özeti", "Detaylı Bulgular", "Teknik Ayrıntılar", "Sınırlamalar ve Yasal Uyarı",
        "Şifreleme ğüşıöç İİ", "Ayşe Yılmaz", "Örnek Güvenilir CA",
        "Kullanıcı izin beyanı", "Tamamlanamadı", "Atlandı", "01.01.2026 09:30 UTC",
    ]:
        assert expected in text, f"PDF'te '{expected}' bulunamadı"


def test_pdf_marks_probable_findings(full_scan, tmp_path):
    text = pdf_text(write_pdf(full_scan, tmp_path / "rapor.pdf"))
    assert "Olası (manuel doğrulama önerilir)" in text
    assert "Bu bulgu doğrulanmamıştır" in text


def test_pdf_escapes_markup_in_evidence(full_scan, tmp_path):
    # "<script>" metni PDF'i bozmamalı, olduğu gibi görünmeli
    text = pdf_text(write_pdf(full_scan, tmp_path / "rapor.pdf"))
    assert "<script>" in text


def test_pdf_shows_grade(full_scan, tmp_path):
    text = pdf_text(write_pdf(full_scan, tmp_path / "rapor.pdf"))
    assert full_scan.risk.grade in text
    assert f"{full_scan.risk.score} / 100" in text
    assert "bazı kontroller tamamlanamadı" in text


def test_pdf_without_findings(lab_authorization, tmp_path):
    scan = apply_risk(ScanResult(target="ornek.com", authorization=lab_authorization,
                                 checks=[CheckResult(check_name="tls", status=CheckStatus.COMPLETED)]))
    text = pdf_text(write_pdf(scan, tmp_path / "rapor.pdf"))
    assert "bulgu tespit edilmedi" in text
    assert "Detaylı Bulgular" not in text


def test_pdf_many_findings_paginate(lab_authorization, make_finding, tmp_path):
    findings = [make_finding(id=f"TST-{i:03d}", description="Uzun açıklama. " * 40) for i in range(30)]
    scan = apply_risk(ScanResult(target="ornek.com", authorization=lab_authorization,
                                 checks=[CheckResult(check_name="headers", status=CheckStatus.COMPLETED,
                                                     findings=findings)]))
    path = write_pdf(scan, tmp_path / "rapor.pdf")
    assert len(PdfReader(path).pages) > 5
    assert "Sayfa 3" in pdf_text(path)


def test_pdf_write_failure_leaves_no_temp_file(full_scan, tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("disk dolu")

    monkeypatch.setattr("sefalet.reporting.pdf_report.os.replace", fail)
    with pytest.raises(OSError):
        write_pdf(full_scan, tmp_path / "rapor.pdf")
    assert list(tmp_path.iterdir()) == []
