"""Veri modelleri: taramanın "ortak dili".

Bütün kontrol modülleri (TLS, DNS, header, port) sonuçlarını burada
tanımlanan aynı yapılarla döndürür. Böylece risk sınıflandırma ve
raporlama kodları, hangi modülden geldiğine bakmadan her bulguyu
aynı şekilde işleyebilir.

Kullandığımız kütüphane: pydantic
  - Bir sınıfın alanlarını ve tiplerini tanımlarız.
  - pydantic, yanlış veri gelirse (ör. boş başlık, geçersiz ID)
    hemen `ValidationError` fırlatır. Hatalı bulgu rapora sızamaz.
  - `.model_dump_json()` ile tek satırda JSON'a çeviririz.

Hiyerarşi:
    ScanResult            → bir taramanın tamamı
      ├─ AuthorizationInfo  → hedefin taranma izni nasıl doğrulandı
      └─ CheckResult[]      → her kontrol modülünün sonucu
           └─ Finding[]       → tek tek bulgular
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, Field, model_validator

from sefalet import __version__

# JSON çıktısının biçim sürümü. Alan ekler/değiştirirsek bunu artırırız;
# böylece eski raporları okuyan programlar bozulmaz.
SCHEMA_VERSION = "1.0"


def _utc_now() -> datetime:
    """Şu anki zamanı UTC saat diliminde döndürür.

    Saat dilimi bilgisi olmayan ("naive") tarihler farklı ülkelerde
    yanlış yorumlanabilir; bu yüzden her zaman UTC kullanıyoruz.
    """
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Sabit seçenek listeleri (Enum)
#
# StrEnum: Değerleri metin olan sabit listeler. JSON'a "high" gibi sade
# metin olarak yazılır. JSON'da İngilizce kod, raporda Türkçe etiket
# kullanıyoruz: kod değişmez, etiket ileride başka dile çevrilebilir.
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Bulgunun risk seviyesi: sorun gerçekse etkisi ne kadar büyük?"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def label_tr(self) -> str:
        """Raporda gösterilecek Türkçe ad."""
        return _SEVERITY_LABELS[self]

    @property
    def rank(self) -> int:
        """Sıralama için sayı: büyük sayı = daha ciddi."""
        return _SEVERITY_RANKS[self]


_SEVERITY_LABELS = {
    Severity.CRITICAL: "Kritik",
    Severity.HIGH: "Yüksek",
    Severity.MEDIUM: "Orta",
    Severity.LOW: "Düşük",
    Severity.INFO: "Bilgi",
}
_SEVERITY_RANKS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(StrEnum):
    """Bulgunun güven düzeyi: bu sorunun gerçekten var olduğundan ne kadar eminiz?

    Risk seviyesinden AYRI bir eksendir. Örnek: 3306 (MySQL) portunun açık
    olması "Yüksek" risktir, ama arkasında gerçekten MySQL olduğunu
    doğrulamadığımız için güven düzeyi "Olası" olur. Raporlar doğrulanmamış
    bulguyu asla kesin açık gibi göstermemelidir.
    """

    CONFIRMED = "confirmed"          # Doğrudan gözlemlendi (ör. sertifika süresi dolmuş)
    PROBABLE = "probable"            # Belirti var, manuel doğrulama gerekir
    INFORMATIONAL = "informational"  # Sorun değil; bağlam için bilgi

    @property
    def label_tr(self) -> str:
        return _CONFIDENCE_LABELS[self]


_CONFIDENCE_LABELS = {
    Confidence.CONFIRMED: "Doğrulandı",
    Confidence.PROBABLE: "Olası (manuel doğrulama önerilir)",
    Confidence.INFORMATIONAL: "Bilgi amaçlı",
}


class CheckStatus(StrEnum):
    """Bir kontrol modülünün nasıl sonlandığı."""

    COMPLETED = "completed"  # Kontrol sorunsuz çalıştı (bulgu olsa da olmasa da)
    ERROR = "error"          # Kontrol bir hata nedeniyle tamamlanamadı
    SKIPPED = "skipped"      # Kontrol bilerek çalıştırılmadı (ör. port taraması kapalı)

    @property
    def label_tr(self) -> str:
        return _STATUS_LABELS[self]


_STATUS_LABELS = {
    CheckStatus.COMPLETED: "Tamamlandı",
    CheckStatus.ERROR: "Tamamlanamadı",
    CheckStatus.SKIPPED: "Atlandı",
}


class AuthorizationMethod(StrEnum):
    """Hedefi tarama izninin nasıl doğrulandığı."""

    DNS_TXT = "dns_txt"          # Alan adına özel TXT kaydı eklendi
    HTTP_FILE = "http_file"      # Siteye /.well-known/ altında doğrulama dosyası kondu
    DECLARATION = "declaration"  # Kullanıcı yazılı izin beyanı verdi (yalnızca pasif kontroller)
    LAB = "lab"                  # Kullanıcının kendi yerel test ortamı

    @property
    def label_tr(self) -> str:
        return _AUTH_LABELS[self]

    @property
    def is_technical(self) -> bool:
        """Teknik (kanıtlanabilir) doğrulama mı?

        Port kontrolü gibi aktif kontroller yalnızca teknik doğrulamayla
        çalışabilir. Beyan tek başına yeterli değildir.
        """
        return self in (AuthorizationMethod.DNS_TXT, AuthorizationMethod.HTTP_FILE,
                        AuthorizationMethod.LAB)


_AUTH_LABELS = {
    AuthorizationMethod.DNS_TXT: "DNS TXT kaydı ile doğrulandı",
    AuthorizationMethod.HTTP_FILE: "HTTP doğrulama dosyası ile doğrulandı",
    AuthorizationMethod.DECLARATION: "Kullanıcı izin beyanı (teknik doğrulama yok)",
    AuthorizationMethod.LAB: "Yerel laboratuvar ortamı",
}


# ---------------------------------------------------------------------------
# Modeller
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """Tek bir güvenlik bulgusu.

    Örnek:
        Finding(
            id="HDR-002",
            category="HTTP Güvenlik Başlıkları",
            title="Content-Security-Policy başlığı bulunamadı",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            evidence="Yanıt başlıklarında CSP yok (HTTP 200)",
            description="...",
            recommendation="...",
        )
    """

    # Bulgu kodu: 2-5 büyük harf, tire, 3 rakam (ör. "TLS-001", "HDR-012").
    # Sabit kodlar sayesinde müşteri iki taramayı karşılaştırabilir.
    id: str = Field(pattern=r"^[A-Z]{2,5}-\d{3}$")
    category: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    confidence: Confidence
    # Kanıt: bulguya neden vardığımızı gösteren somut gözlem.
    # Zorunlu tuttuk: kanıtsız bulgu raporlanmaz.
    evidence: str = Field(min_length=1)
    description: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)


class CheckResult(BaseModel):
    """Bir kontrol modülünün (ör. TLS kontrolü) çalışma sonucu."""

    check_name: str = Field(min_length=1)   # Ör. "tls", "headers", "dns", "ports"
    status: CheckStatus
    findings: list[Finding] = Field(default_factory=list)
    # Hata veya atlanma nedeni (kullanıcıya gösterilecek Türkçe mesaj)
    message: str | None = None
    duration_seconds: float = Field(default=0.0, ge=0)
    # Bulgu olmayan ama raporda gösterilecek bilgiler (ör. sertifika sağlayıcısı,
    # bitiş tarihi, TLS sürümü). Değerler JSON'a yazılabilir olmalı (metin, sayı, liste).
    details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _message_required_when_not_completed(self) -> CheckResult:
        """Kontrol tamamlanmadıysa nedenini yazmak zorunlu.

        Raporu okuyan kişi "bu kontrol neden yok?" sorusunun cevabını
        her zaman görebilmeli.
        """
        if self.status != CheckStatus.COMPLETED and not self.message:
            raise ValueError(
                f"'{self.status.value}' durumundaki kontrol için 'message' (neden) zorunludur."
            )
        return self


class AuthorizationInfo(BaseModel):
    """Hedefin taranma izninin kaydı (denetim izi)."""

    method: AuthorizationMethod
    verified_at: AwareDatetime = Field(default_factory=_utc_now)
    # Doğrulamanın ayrıntısı: ör. bulunan TXT kaydı veya beyan metni
    details: str = Field(min_length=1)


class ScanResult(BaseModel):
    """Bir taramanın tüm sonucu. JSON ve PDF raporları bundan üretilir."""

    schema_version: str = SCHEMA_VERSION
    scanner_version: str = __version__
    # Her taramaya benzersiz kimlik verilir (raporları takip etmek için)
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str = Field(min_length=1)
    started_at: AwareDatetime = Field(default_factory=_utc_now)
    finished_at: AwareDatetime | None = None
    authorization: AuthorizationInfo
    checks: list[CheckResult] = Field(default_factory=list)

    def all_findings(self) -> list[Finding]:
        """Bütün kontrollerin bulgularını, en ciddiden en hafife sıralı döndürür."""
        findings = [f for check in self.checks for f in check.findings]
        # sorted() aynı seviyedekilerin sırasını korur; ID ile ikinci sıralama yapıyoruz
        return sorted(findings, key=lambda f: (-f.severity.rank, f.id))

    def severity_counts(self) -> dict[Severity, int]:
        """Her risk seviyesinde kaç bulgu var? Sıfır olanlar da listelenir."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.all_findings():
            counts[finding.severity] += 1
        return counts

    def to_json(self) -> str:
        """Sonucu okunaklı (girintili) JSON metnine çevirir."""
        return self.model_dump_json(indent=2)
