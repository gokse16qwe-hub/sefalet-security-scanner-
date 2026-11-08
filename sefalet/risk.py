"""Risk sınıflandırma ve genel not hesaplama.

Yöntem (raporda da açıkça yazılır, çünkü ticari bir üründe puanlamanın
şeffaf olması gerekir):

1. 100 puandan başlanır.
2. Her bulgu, risk seviyesine göre puan düşürür:
       Kritik 40 · Yüksek 20 · Orta 8 · Düşük 3 · Bilgi 0
3. "Olası" güven düzeyindeki bulgular yarım puan düşürür, çünkü
   doğrulanmamışlardır. "Bilgi amaçlı" bulgular puan düşürmez.
4. Puan 0'ın altına inmez. Not: A ≥ 90 · B ≥ 80 · C ≥ 65 · D ≥ 50 · F < 50
5. Üst sınırlar: Doğrulanmış bir Kritik bulgu varsa not en fazla F,
   doğrulanmış bir Yüksek bulgu varsa en fazla C olabilir. Böylece çok
   sayıda küçük sorunu olmayan ama bir ciddi açığı olan site "A" alamaz.
6. Bir kontrol hata nedeniyle tamamlanamadıysa özet "eksik" işaretlenir.
"""

from __future__ import annotations

from sefalet.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    RiskSummary,
    ScanResult,
    Severity,
)

PENALTIES = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
CONFIDENCE_FACTOR = {
    Confidence.CONFIRMED: 1.0,
    Confidence.PROBABLE: 0.5,
    Confidence.INFORMATIONAL: 0.0,
}
GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")]
GRADE_ORDER = "ABCDEF"

METHODOLOGY_TR = (
    "Puanlama 100 üzerinden başlar. Her bulgu risk seviyesine göre puan düşürür "
    "(Kritik 40, Yüksek 20, Orta 8, Düşük 3, Bilgi 0). Manuel doğrulama gerektiren "
    "'olası' bulgular yarım puan düşürür; bilgi amaçlı bulgular puanı etkilemez. "
    "Not aralıkları: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50. Doğrulanmış Kritik "
    "bulgu varsa not en fazla F, doğrulanmış Yüksek bulgu varsa en fazla C olur. "
    "Bu puan yalnızca taranan yapılandırma kontrollerini yansıtır; sitenin genel "
    "güvenlik düzeyi hakkında kesin bir yargı değildir."
)


def _grade_for(score: int) -> str:
    return next(grade for threshold, grade in GRADE_THRESHOLDS if score >= threshold)


def _cap(grade: str, worst_allowed: str) -> str:
    """Notu verilen üst sınırdan daha iyi olamayacak şekilde sınırlar."""
    return max(grade, worst_allowed, key=GRADE_ORDER.index)


def calculate_risk(findings: list[Finding], checks: list[CheckResult]) -> RiskSummary:
    """Bulgulardan genel risk özetini hesaplar."""
    penalty = sum(PENALTIES[f.severity] * CONFIDENCE_FACTOR[f.confidence] for f in findings)
    score = max(0, round(100 - penalty))
    grade = _grade_for(score)

    confirmed = {f.severity for f in findings if f.confidence is Confidence.CONFIRMED}
    if Severity.CRITICAL in confirmed:
        grade = _cap(grade, "F")
    elif Severity.HIGH in confirmed:
        grade = _cap(grade, "C")

    counts = {severity: 0 for severity in Severity}
    for f in findings:
        counts[f.severity] += 1
    probable = sum(1 for f in findings if f.confidence is Confidence.PROBABLE)
    errored = [c.check_name for c in checks if c.status is CheckStatus.ERROR]

    return RiskSummary(
        score=score,
        grade=grade,
        counts=counts,
        probable_count=probable,
        complete=not errored,
        summary_tr=_summary_text(grade, counts, probable, errored),
    )


def _summary_text(grade: str, counts: dict[Severity, int], probable: int,
                  errored: list[str]) -> str:
    serious = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    if serious:
        text = f"Genel not {grade}. Öncelikli ele alınması gereken {serious} ciddi bulgu var."
    elif counts[Severity.MEDIUM]:
        text = (f"Genel not {grade}. Ciddi bulgu yok; {counts[Severity.MEDIUM]} orta seviye "
                "yapılandırma iyileştirmesi öneriliyor.")
    elif counts[Severity.LOW]:
        text = f"Genel not {grade}. Yalnızca düşük seviyeli iyileştirme önerileri var."
    else:
        text = f"Genel not {grade}. Taranan kontrollerde önemli bir bulguya rastlanmadı."
    if probable:
        text += f" {probable} bulgu manuel doğrulama gerektiriyor."
    if errored:
        text += (f" Bazı kontroller tamamlanamadı ({', '.join(errored)}); sonuçlar eksik "
                 "olabilir.")
    return text


def apply_risk(scan: ScanResult) -> ScanResult:
    """Taramanın risk özetini hesaplayıp `scan.risk` alanına yazar."""
    scan.risk = calculate_risk(scan.all_findings(), scan.checks)
    return scan
