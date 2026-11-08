"""Tarama yöneticisi: bütün kontrolleri sırayla çalıştırıp tek sonuçta toplar.

Bu dosya, CLI'dan (ve ileride web API'den) çağrılan ana giriş noktasıdır.
Yetki doğrulama BURADA YAPILMAZ: çağıran taraf doğrulamayı yapıp sonucu
(`AuthorizationInfo`) verir. Ancak burada politikanın tekrar kontrolü
yapılır, böylece doğrulamasız bir tarama yanlışlıkla başlatılamaz.

Hata yönetimi: Bir kontrol beklenmedik şekilde çökse bile tarama durmaz;
o kontrol "tamamlanamadı" olarak işaretlenir ve hata loglanır.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from sefalet.authorization import ensure_allowed
from sefalet.checks import dns_check, headers_check, port_check, tls_check
from sefalet.models import AuthorizationInfo, CheckResult, CheckStatus, ScanResult
from sefalet.risk import apply_risk
from sefalet.target import Target

logger = logging.getLogger(__name__)

# İlerleme bildirimi: (kontrol adı, "başladı"/"bitti") → CLI'da durum göstermek için
ProgressCallback = Callable[[str, str], None]

CHECK_LABELS_TR = {
    "tls": "SSL/TLS",
    "headers": "HTTP güvenlik başlıkları",
    "dns": "DNS kayıtları",
    "ports": "TCP port kontrolü",
}


def _run_safely(name: str, func: Callable[[], CheckResult]) -> CheckResult:
    """Kontrolü çalıştırır; beklenmeyen bir hata olursa ERROR sonucu döndürür."""
    try:
        return func()
    except Exception as exc:  # noqa: BLE001 - tek bir modülün çökmesi taramayı durdurmamalı
        logger.exception("'%s' kontrolünde beklenmeyen hata", name)
        return CheckResult(
            check_name=name,
            status=CheckStatus.ERROR,
            message=f"Kontrol sırasında beklenmeyen bir hata oluştu ({type(exc).__name__}). "
                    "Ayrıntılar log kaydında.",
        )


def run_scan(
    target: Target,
    authorization: AuthorizationInfo,
    *,
    enable_port_scan: bool = False,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Taramayı çalıştırır ve risk özeti hesaplanmış sonucu döndürür.

    Raises:
        AuthorizationError: Yetki pasif kontroller için bile yetersizse.
    """
    ensure_allowed(authorization, active=False)
    if enable_port_scan:
        # Aktif kontrol istendiyse yetkiyi baştan kontrol et (erken ve net hata)
        ensure_allowed(authorization, active=True)

    scan = ScanResult(
        target=target.label,
        target_ips=list(target.ip_addresses),
        authorization=authorization,
    )

    steps: list[tuple[str, Callable[[], CheckResult]]] = [
        ("tls", lambda: tls_check.check_tls(target)),
        ("headers", lambda: headers_check.check_headers(target)),
        ("dns", lambda: dns_check.check_dns(target)),
        ("ports", lambda: port_check.check_ports(target, authorization, enabled=enable_port_scan)),
    ]
    for name, func in steps:
        if progress:
            progress(name, "başladı")
        result = _run_safely(name, func)
        scan.checks.append(result)
        logger.info("%s: %s (%d bulgu, %.1f sn)", name, result.status.value,
                    len(result.findings), result.duration_seconds)
        if progress:
            progress(name, "bitti")

    scan.finished_at = datetime.now(timezone.utc)
    return apply_risk(scan)
