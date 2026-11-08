"""Testlerde ortak kullanılan yardımcılar ("fixture").

pytest, test fonksiyonlarının parametre adına bakarak buradaki
fixture'ı otomatik olarak çağırır ve sonucunu teste verir.
"""

import pytest

from sefalet.models import AuthorizationInfo, AuthorizationMethod, Confidence, Finding, Severity


@pytest.fixture
def make_finding():
    """Test için kolayca bulgu üreten fonksiyon döndürür.

    Kullanım: make_finding(id="TLS-001", severity=Severity.HIGH)
    Verilmeyen alanlar makul varsayılanlarla doldurulur.
    """

    def _make(**overrides) -> Finding:
        data = {
            "id": "TST-001",
            "category": "Test",
            "title": "Test bulgusu",
            "severity": Severity.LOW,
            "confidence": Confidence.CONFIRMED,
            "evidence": "Test kanıtı",
        }
        data.update(overrides)
        return Finding(**data)

    return _make


@pytest.fixture
def lab_authorization() -> AuthorizationInfo:
    """Testlerde kullanılacak örnek yetki kaydı."""
    return AuthorizationInfo(method=AuthorizationMethod.LAB, details="Yerel test ortamı")
