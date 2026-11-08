"""risk.py için testler."""

import pytest

from sefalet.models import CheckResult, CheckStatus, Confidence, ScanResult, Severity
from sefalet.risk import apply_risk, calculate_risk


def ok_checks():
    return [CheckResult(check_name="tls", status=CheckStatus.COMPLETED)]


def test_no_findings_is_a_100(make_finding):
    risk = calculate_risk([], ok_checks())
    assert (risk.score, risk.grade, risk.complete) == (100, "A", True)
    assert "önemli bir bulguya rastlanmadı" in risk.summary_tr


def test_info_findings_do_not_reduce_score(make_finding):
    findings = [make_finding(severity=Severity.INFO) for _ in range(10)]
    assert calculate_risk(findings, ok_checks()).score == 100


@pytest.mark.parametrize(
    ("severities", "score", "grade"),
    [
        ([Severity.LOW] * 3, 91, "A"),
        ([Severity.MEDIUM, Severity.LOW], 89, "B"),
        ([Severity.MEDIUM] * 3, 76, "C"),
        ([Severity.MEDIUM] * 5, 60, "D"),
        ([Severity.MEDIUM] * 7, 44, "F"),
        ([Severity.MEDIUM] * 20, 0, "F"),  # 0'ın altına inmez
    ],
)
def test_score_and_grade(make_finding, severities, score, grade):
    findings = [make_finding(severity=s) for s in severities]
    risk = calculate_risk(findings, ok_checks())
    assert (risk.score, risk.grade) == (score, grade)


def test_probable_findings_count_half(make_finding):
    findings = [make_finding(severity=Severity.HIGH, confidence=Confidence.PROBABLE)]
    risk = calculate_risk(findings, ok_checks())
    assert risk.score == 90
    assert risk.grade == "A"  # Doğrulanmamış Yüksek bulgu not sınırı uygulamaz
    assert risk.probable_count == 1
    assert "manuel doğrulama" in risk.summary_tr


def test_informational_confidence_ignored(make_finding):
    findings = [make_finding(severity=Severity.MEDIUM, confidence=Confidence.INFORMATIONAL)]
    assert calculate_risk(findings, ok_checks()).score == 100


def test_confirmed_high_caps_grade_at_c(make_finding):
    risk = calculate_risk([make_finding(severity=Severity.HIGH)], ok_checks())
    assert risk.score == 80
    assert risk.grade == "C"
    assert "1 ciddi bulgu" in risk.summary_tr


def test_confirmed_critical_caps_grade_at_f(make_finding):
    risk = calculate_risk([make_finding(severity=Severity.CRITICAL)], ok_checks())
    assert (risk.score, risk.grade) == (60, "F")


def test_cap_never_improves_grade(make_finding):
    findings = [make_finding(severity=Severity.HIGH)] + [make_finding(severity=Severity.MEDIUM)] * 6
    assert calculate_risk(findings, ok_checks()).grade == "F"


def test_counts(make_finding):
    findings = [make_finding(severity=Severity.LOW), make_finding(severity=Severity.LOW),
                make_finding(severity=Severity.HIGH)]
    counts = calculate_risk(findings, ok_checks()).counts
    assert counts[Severity.LOW] == 2 and counts[Severity.HIGH] == 1 and counts[Severity.INFO] == 0


def test_errored_check_marks_incomplete():
    checks = ok_checks() + [CheckResult(check_name="dns", status=CheckStatus.ERROR, message="x")]
    risk = calculate_risk([], checks)
    assert risk.complete is False
    assert "dns" in risk.summary_tr


def test_skipped_check_is_not_incomplete():
    checks = ok_checks() + [CheckResult(check_name="ports", status=CheckStatus.SKIPPED, message="x")]
    assert calculate_risk([], checks).complete is True


def test_apply_risk_and_json_roundtrip(lab_authorization, make_finding):
    check = CheckResult(check_name="tls", status=CheckStatus.COMPLETED,
                        findings=[make_finding(severity=Severity.MEDIUM)])
    scan = apply_risk(ScanResult(target="ornek.com", authorization=lab_authorization, checks=[check]))
    assert (scan.risk.score, scan.risk.grade) == (92, "A")
    restored = ScanResult.model_validate_json(scan.to_json())
    assert restored.risk == scan.risk
