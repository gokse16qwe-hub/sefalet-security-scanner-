"""models.py için testler.

Her test fonksiyonu `test_` ile başlar; pytest bunları otomatik bulur.
`assert` ifadesi yanlışsa test başarısız olur.
`pytest.raises(...)` bloğu, içindeki kodun hata fırlatmasını BEKLER.
"""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from sefalet.models import (
    SCHEMA_VERSION,
    AuthorizationInfo,
    AuthorizationMethod,
    CheckResult,
    CheckStatus,
    Confidence,
    ScanResult,
    Severity,
)

# --- Enum'lar -------------------------------------------------------------


def test_severity_turkish_labels():
    assert Severity.CRITICAL.label_tr == "Kritik"
    assert Severity.INFO.label_tr == "Bilgi"


def test_every_enum_member_has_turkish_label():
    # Yeni bir seviye eklenip etiketi unutulursa bu test yakalar.
    for enum_cls in (Severity, Confidence, CheckStatus, AuthorizationMethod):
        for member in enum_cls:
            assert member.label_tr, f"{enum_cls.__name__}.{member.name} etiketi yok"


def test_severity_rank_order():
    ranks = [s.rank for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                              Severity.LOW, Severity.INFO)]
    assert ranks == sorted(ranks, reverse=True)


def test_only_technical_methods_allow_active_checks():
    assert AuthorizationMethod.DNS_TXT.is_technical
    assert AuthorizationMethod.HTTP_FILE.is_technical
    assert AuthorizationMethod.LAB.is_technical
    # Beyan, port kontrolü için yeterli değil
    assert not AuthorizationMethod.DECLARATION.is_technical


# --- Finding --------------------------------------------------------------


def test_valid_finding(make_finding):
    finding = make_finding(id="HDR-002", severity=Severity.MEDIUM)
    assert finding.id == "HDR-002"
    assert finding.references == []


@pytest.mark.parametrize("bad_id", ["hdr-002", "HDR2", "HDR-02", "H-001", "TOOLONG-001", ""])
def test_finding_rejects_invalid_id(make_finding, bad_id):
    with pytest.raises(ValidationError):
        make_finding(id=bad_id)


@pytest.mark.parametrize("field", ["title", "category", "evidence"])
def test_finding_rejects_empty_required_text(make_finding, field):
    # Kanıtsız veya başlıksız bulgu rapora girmemeli
    with pytest.raises(ValidationError):
        make_finding(**{field: ""})


def test_finding_rejects_unknown_severity(make_finding):
    with pytest.raises(ValidationError):
        make_finding(severity="very-bad")


def test_finding_accepts_string_enum_values(make_finding):
    # JSON'dan geri okurken değerler metin olarak gelir
    finding = make_finding(severity="high", confidence="probable")
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.PROBABLE


# --- CheckResult ----------------------------------------------------------


def test_completed_check_without_message_is_ok():
    result = CheckResult(check_name="tls", status=CheckStatus.COMPLETED)
    assert result.findings == []


@pytest.mark.parametrize("status", [CheckStatus.ERROR, CheckStatus.SKIPPED])
def test_non_completed_check_requires_message(status):
    with pytest.raises(ValidationError, match="message"):
        CheckResult(check_name="ports", status=status)


def test_skipped_check_with_message():
    result = CheckResult(
        check_name="ports",
        status=CheckStatus.SKIPPED,
        message="Port kontrolü varsayılan olarak kapalıdır.",
    )
    assert result.status.label_tr == "Atlandı"


def test_negative_duration_rejected():
    with pytest.raises(ValidationError):
        CheckResult(check_name="dns", status=CheckStatus.COMPLETED, duration_seconds=-1)


# --- AuthorizationInfo ----------------------------------------------------


def test_authorization_requires_details():
    with pytest.raises(ValidationError):
        AuthorizationInfo(method=AuthorizationMethod.DNS_TXT, details="")


def test_authorization_rejects_naive_datetime():
    # Saat dilimi olmayan tarih kabul edilmez
    with pytest.raises(ValidationError):
        AuthorizationInfo(method=AuthorizationMethod.LAB, details="x",
                          verified_at=datetime(2026, 1, 1))


# --- ScanResult -----------------------------------------------------------


def _scan_with_findings(auth, make_finding) -> ScanResult:
    tls = CheckResult(
        check_name="tls",
        status=CheckStatus.COMPLETED,
        findings=[
            make_finding(id="TLS-002", severity=Severity.LOW),
            make_finding(id="TLS-001", severity=Severity.CRITICAL),
        ],
    )
    headers = CheckResult(
        check_name="headers",
        status=CheckStatus.COMPLETED,
        findings=[
            make_finding(id="HDR-001", severity=Severity.MEDIUM),
            make_finding(id="HDR-002", severity=Severity.LOW),
        ],
    )
    ports = CheckResult(check_name="ports", status=CheckStatus.SKIPPED,
                        message="Kapalı")
    return ScanResult(target="ornek.com", authorization=auth, checks=[tls, headers, ports])


def test_scan_defaults(lab_authorization):
    scan = ScanResult(target="ornek.com", authorization=lab_authorization)
    assert scan.schema_version == SCHEMA_VERSION
    assert scan.started_at.tzinfo is not None
    assert scan.finished_at is None
    assert len(scan.scan_id) == 36  # UUID biçimi


def test_each_scan_gets_unique_id(lab_authorization):
    a = ScanResult(target="ornek.com", authorization=lab_authorization)
    b = ScanResult(target="ornek.com", authorization=lab_authorization)
    assert a.scan_id != b.scan_id


def test_all_findings_sorted_by_severity_then_id(lab_authorization, make_finding):
    scan = _scan_with_findings(lab_authorization, make_finding)
    assert [f.id for f in scan.all_findings()] == ["TLS-001", "HDR-001", "HDR-002", "TLS-002"]


def test_severity_counts_include_zeros(lab_authorization, make_finding):
    counts = _scan_with_findings(lab_authorization, make_finding).severity_counts()
    assert counts == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 0,
        Severity.MEDIUM: 1,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }


def test_json_roundtrip(lab_authorization, make_finding):
    # JSON'a yazıp geri okuduğumuzda aynı veriyi elde etmeliyiz
    scan = _scan_with_findings(lab_authorization, make_finding)
    text = scan.to_json()

    data = json.loads(text)
    assert data["target"] == "ornek.com"
    assert data["checks"][0]["findings"][1]["severity"] == "critical"
    assert data["authorization"]["method"] == "lab"

    restored = ScanResult.model_validate_json(text)
    assert restored == scan


def test_json_keeps_turkish_characters(lab_authorization, make_finding):
    finding = make_finding(title="Şifreleme ayarı güçsüz: İçerik ğüşıöç")
    check = CheckResult(check_name="tls", status=CheckStatus.COMPLETED, findings=[finding])
    scan = ScanResult(target="ornek.com", authorization=lab_authorization, checks=[check])
    restored = ScanResult.model_validate_json(scan.to_json())
    assert restored.checks[0].findings[0].title == "Şifreleme ayarı güçsüz: İçerik ğüşıöç"
