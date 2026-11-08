"""Sınırlı TCP port kontrolü (aktif kontrol: VARSAYILAN OLARAK KAPALI).

Ne yapar?
    Sabit, kısa bir port listesindeki her porta normal bir TCP bağlantısı
    açmayı dener ("TCP connect"). Bağlantı kurulursa port açıktır; hemen
    kapatılır. Hiçbir veri gönderilmez veya okunmaz (banner okuma yok).

Ne YAPMAZ?
    - SYN/stealth tarama, ham paket gönderimi (root gerektirmez)
    - Port aralığı tarama (1-65535)
    - Servis sürümü tespiti, exploit, parola denemesi

Çalışma şartları (üçü birden):
    1. Kullanıcı açıkça etkinleştirmiş olmalı (CLI: --enable-port-scan)
    2. Hedef teknik olarak doğrulanmış olmalı (DNS TXT, HTTP dosyası, lab)
       → izin beyanı YETERLİ DEĞİL
    3. Yalnızca hedefin çözümlenmiş ilk IP adresi kontrol edilir

Güven düzeyi: Açık bir port, o portta beklenen servisin çalıştığını
KANITLAMAZ. Bu yüzden servis bazlı bulgular "Olası" olarak raporlanır.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from sefalet.authorization import AuthorizationError, ensure_allowed
from sefalet.models import AuthorizationInfo, CheckResult, CheckStatus, Confidence, Finding, Severity
from sefalet.target import Target

CHECK_NAME = "ports"
CATEGORY = "Ağ Servisleri (TCP Port)"
CONNECT_TIMEOUT = 1.5  # saniye
MAX_WORKERS = 10       # aynı anda en fazla bu kadar bağlantı
MAX_PORTS = 25         # tek taramada en fazla bu kadar port

OPEN = "açık"
CLOSED = "kapalı"
FILTERED = "filtrelenmiş"
ERROR = "hata"


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    finding_id: str | None          # None → beklenen/normal servis, ayrı bulgu üretmez
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    recommendation: str = ""


_DB_RECOMMENDATION = ("Veritabanı/servis portunu internete kapatın; yalnızca uygulama sunucusunun "
                      "IP adresine izin veren güvenlik duvarı kuralı uygulayın veya VPN kullanın.")


def _exposed(name: str, id_: str, severity: Severity, why: str,
             recommendation: str = _DB_RECOMMENDATION) -> ServiceInfo:
    return ServiceInfo(
        name=name, finding_id=id_, severity=severity,
        title=f"{name} portu internetten erişilebilir görünüyor",
        description=(f"Bu port genellikle {name} tarafından kullanılır. {why} Portun açık olması, "
                     f"arkasında gerçekten {name} çalıştığını kanıtlamaz; manuel doğrulama gerekir."),
        recommendation=recommendation,
    )


# Kontrol edilen sabit port listesi
SERVICES: dict[int, ServiceInfo] = {
    21: _exposed("FTP", "PRT-021", Severity.MEDIUM,
                 "FTP, parolaları ve dosyaları şifrelemeden iletir.",
                 "FTP yerine SFTP veya FTPS kullanın; gerekmiyorsa servisi kapatın."),
    22: ServiceInfo("SSH", None),
    23: _exposed("Telnet", "PRT-023", Severity.HIGH,
                 "Telnet tüm trafiği (parolalar dahil) şifrelemeden iletir.",
                 "Telnet'i kapatın ve SSH kullanın."),
    25: ServiceInfo("SMTP", None),
    53: ServiceInfo("DNS", None),
    80: ServiceInfo("HTTP", None),
    110: _exposed("POP3", "PRT-110", Severity.LOW,
                  "Şifrelemesiz POP3, e-posta parolalarını açık metin olarak iletebilir.",
                  "Yalnızca şifreli POP3S (995) kullanın."),
    143: _exposed("IMAP", "PRT-143", Severity.LOW,
                  "Şifrelemesiz IMAP, e-posta parolalarını açık metin olarak iletebilir.",
                  "Yalnızca şifreli IMAPS (993) kullanın."),
    443: ServiceInfo("HTTPS", None),
    445: _exposed("SMB", "PRT-445", Severity.HIGH,
                  "SMB'nin internete açık olması fidye yazılımı saldırılarında sık kullanılan bir giriş noktasıdır."),
    1433: _exposed("Microsoft SQL Server", "PRT-433", Severity.HIGH,
                   "Veritabanlarının internete açık olması parola deneme ve veri sızıntısı riskini artırır."),
    3306: _exposed("MySQL/MariaDB", "PRT-306", Severity.HIGH,
                   "Veritabanlarının internete açık olması parola deneme ve veri sızıntısı riskini artırır."),
    3389: _exposed("Uzak Masaüstü (RDP)", "PRT-389", Severity.MEDIUM,
                   "İnternete açık RDP, parola deneme saldırılarının yaygın hedefidir.",
                   "RDP'yi VPN arkasına alın veya ağ seviyesinde kimlik doğrulama ve IP kısıtlaması uygulayın."),
    5432: _exposed("PostgreSQL", "PRT-432", Severity.HIGH,
                   "Veritabanlarının internete açık olması parola deneme ve veri sızıntısı riskini artırır."),
    5900: _exposed("VNC", "PRT-900", Severity.HIGH,
                   "VNC çoğu zaman zayıf kimlik doğrulamayla çalışır ve ekran kontrolü sağlar.",
                   "VNC'yi internete kapatın; gerekiyorsa SSH tüneli veya VPN üzerinden kullanın."),
    6379: _exposed("Redis", "PRT-379", Severity.HIGH,
                   "Redis varsayılan kurulumda parola istemez."),
    8080: ServiceInfo("HTTP (alternatif)", None),
    8443: ServiceInfo("HTTPS (alternatif)", None),
    9200: _exposed("Elasticsearch", "PRT-920", Severity.HIGH,
                   "Elasticsearch eski sürümlerde varsayılan olarak kimlik doğrulama istemez."),
    11211: _exposed("Memcached", "PRT-211", Severity.HIGH,
                    "Memcached kimlik doğrulama içermez ve DDoS yansıtma saldırılarında kullanılmıştır."),
    27017: _exposed("MongoDB", "PRT-017", Severity.HIGH,
                    "MongoDB eski sürümlerde varsayılan olarak kimlik doğrulama istemez."),
}

DEFAULT_PORTS: tuple[int, ...] = tuple(sorted(SERVICES))


def probe_port(ip: str, port: int, timeout: float = CONNECT_TIMEOUT) -> str:
    """Tek bir porta TCP bağlantısı dener ve durumunu döndürür."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return OPEN
    except ConnectionRefusedError:
        return CLOSED
    except (TimeoutError, socket.timeout):
        return FILTERED
    except OSError:
        return ERROR


def analyze_ports(states: dict[int, str]) -> list[Finding]:
    """Port durumlarından bulgu üretir."""
    findings: list[Finding] = []
    open_ports = sorted(p for p, s in states.items() if s == OPEN)

    for port in open_ports:
        service = SERVICES.get(port)
        if service and service.finding_id:
            findings.append(Finding(
                id=service.finding_id, category=CATEGORY, title=service.title,
                severity=service.severity, confidence=Confidence.PROBABLE,
                evidence=f"TCP {port} portuna bağlantı kuruldu.",
                description=service.description, recommendation=service.recommendation,
            ))

    if open_ports:
        listing = ", ".join(f"{p} ({SERVICES[p].name if p in SERVICES else 'bilinmiyor'})"
                            for p in open_ports)
        findings.append(Finding(
            id="PRT-001", category=CATEGORY, title="Açık TCP portları", severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL, evidence=f"Açık portlar: {listing}.",
            description="Kontrol edilen sınırlı port listesinde bağlantı kabul eden portlar. "
                        "Yalnızca gerçekten gereken servislerin açık olması önerilir.",
            recommendation="Kullanılmayan servisleri kapatın; gerekenleri güvenlik duvarıyla sınırlayın.",
        ))
    return findings


def check_ports(
    target: Target,
    authorization: AuthorizationInfo,
    *,
    enabled: bool = False,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = CONNECT_TIMEOUT,
) -> CheckResult:
    """Port kontrolünü çalıştırır. Hata fırlatmaz.

    Args:
        enabled: Kullanıcı port kontrolünü açıkça etkinleştirdi mi? (varsayılan: hayır)
        ports: Kontrol edilecek portlar (en fazla MAX_PORTS adet).
    """
    started = time.monotonic()

    def result(status, findings=None, message=None, details=None):
        return CheckResult(check_name=CHECK_NAME, status=status, findings=findings or [],
                           message=message, details=details or {},
                           duration_seconds=time.monotonic() - started)

    if not enabled:
        return result(CheckStatus.SKIPPED,
                      message="Port kontrolü varsayılan olarak kapalıdır. Etkinleştirmek için "
                              "teknik doğrulama ve --enable-port-scan seçeneği gerekir.")
    try:
        ensure_allowed(authorization, active=True)
    except AuthorizationError as exc:
        return result(CheckStatus.SKIPPED, message=str(exc))

    if not ports or len(ports) > MAX_PORTS or not all(1 <= p <= 65535 for p in ports):
        return result(CheckStatus.ERROR,
                      message=f"Geçersiz port listesi (1-{MAX_PORTS} adet, 1-65535 arası olmalı).")

    ip = target.primary_ip
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports))) as pool:
        states = dict(zip(ports, pool.map(lambda p: probe_port(ip, p, timeout), ports)))

    details = {
        "ip": ip,
        "ports": {str(p): s for p, s in sorted(states.items())},
        "open": sorted(p for p, s in states.items() if s == OPEN),
    }
    message = None
    if all(s == FILTERED for s in states.values()):
        message = ("Tüm portlar filtrelenmiş görünüyor (yanıt alınamadı). Bir güvenlik duvarı "
                   "bağlantıları engelliyor olabilir; sonuçlar kesin değildir.")
    elif any(s == ERROR for s in states.values()):
        message = "Bazı portlar ağ hatası nedeniyle kontrol edilemedi."
    return result(CheckStatus.COMPLETED, analyze_ports(states), message, details)
