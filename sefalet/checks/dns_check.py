"""DNS kayıtlarının kontrolü.

DNS, alan adlarını IP adreslerine çeviren "internetin telefon rehberi"dir.
Ayrıca e-posta güvenliği ve sertifika güvenliği için önemli kayıtlar tutar:

    SPF   (TXT "v=spf1 ...")      → Bu alan adı adına hangi sunucular e-posta gönderebilir?
    DMARC (_dmarc TXT "v=DMARC1") → SPF/DKIM'den geçemeyen e-postalara ne yapılsın?
    CAA                           → Hangi sertifika otoriteleri bu alan adına sertifika verebilir?
    DS (DNSSEC)                   → DNS yanıtları kriptografik olarak imzalı mı?

Önemli ilke: Bir sorgu zaman aşımına uğrarsa veya başarısız olursa, o kaydı
"yok" saymayız. Yanlışlıkla "SPF kaydı yok" demek, müşteriye hatalı bir
bulgu vermek olur. Başarısız sorgular raporda ayrıca belirtilir.

Bilinen sınırlama: Kayıtlı alan adını (ör. "ornek.com.tr") bulmak için Public
Suffix List gerekir. MVP'de yalnızca baştaki "www." çıkarılır; diğer alt
alan adlarında e-posta kayıtları alt alan adının kendisinde aranır.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import dns.exception
import dns.resolver

from sefalet import config
from sefalet.models import CheckResult, CheckStatus, Confidence, Finding, Severity
from sefalet.target import Target

CHECK_NAME = "dns"
CATEGORY = "DNS ve E-posta Güvenliği"

# Çözümleyici: (ad, kayıt türü) → kayıt metinleri listesi
Resolve = Callable[[str, str], list[str]]


class _QueryFailed(Exception):
    """Sorgu başarısız oldu (zaman aşımı, sunucu hatası). 'Kayıt yok' ile karıştırılmamalı."""


def _default_resolve(name: str, rtype: str) -> list[str]:
    answer = dns.resolver.resolve(name, rtype, lifetime=config.DNS_TIMEOUT)
    if rtype == "TXT":
        # Uzun TXT kayıtları parçalara bölünmüş olabilir: birleştiriyoruz
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer]
    return [r.to_text() for r in answer]


def _finding(id_: str, title: str, severity: Severity, evidence: str, description: str,
             recommendation: str, references: list[str],
             confidence: Confidence = Confidence.CONFIRMED) -> Finding:
    return Finding(id=id_, category=CATEGORY, title=title, severity=severity,
                   confidence=confidence, evidence=evidence, description=description,
                   recommendation=recommendation, references=references)


SPF_REF = ["https://datatracker.ietf.org/doc/html/rfc7208"]
DMARC_REF = ["https://datatracker.ietf.org/doc/html/rfc7489"]
CAA_REF = ["https://datatracker.ietf.org/doc/html/rfc8659"]
DNSSEC_REF = ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"]


# ---------------------------------------------------------------------------
# Analiz (saf fonksiyonlar)
# ---------------------------------------------------------------------------


def analyze_spf(domain: str, txt_records: list[str]) -> list[Finding]:
    spf = [r.strip() for r in txt_records if r.strip().lower().startswith("v=spf1")]
    if not spf:
        return [_finding(
            "DNS-001", "SPF kaydı bulunamadı", Severity.MEDIUM,
            f"{domain} için 'v=spf1' ile başlayan TXT kaydı yok.",
            "SPF olmadan, herhangi bir sunucu bu alan adı adına sahte e-posta gönderebilir "
            "ve alıcı sunucular bunu ayırt etmekte zorlanır (oltalama/phishing riski).",
            "E-posta gönderen servislerinizi listeleyen bir SPF kaydı ekleyin. Alan adı "
            "e-posta göndermiyorsa: v=spf1 -all",
            SPF_REF,
        )]
    if len(spf) > 1:
        return [_finding(
            "DNS-002", "Birden fazla SPF kaydı var", Severity.MEDIUM,
            f"{domain} için {len(spf)} adet SPF kaydı: " + " | ".join(spf),
            "RFC 7208'e göre birden fazla SPF kaydı 'kalıcı hata' (permerror) sayılır; alıcı "
            "sunucular SPF'yi tamamen yok sayabilir.",
            "Kayıtları tek bir SPF kaydında birleştirin.",
            SPF_REF,
        )]

    record = spf[0]
    terms = record.lower().split()
    all_terms = [t for t in terms if t.lstrip("+-~?") == "all"]
    has_redirect = any(t.startswith("redirect=") for t in terms)
    evidence = f"{domain} SPF: {record}"

    if "+all" in all_terms or "all" in all_terms:
        return [_finding(
            "DNS-003", "SPF kaydı tüm sunuculara izin veriyor (+all)", Severity.HIGH, evidence,
            "'+all' (veya önek olmadan 'all') internetteki her sunucunun bu alan adı adına "
            "e-posta göndermesine izin verir; SPF korumasını tamamen ortadan kaldırır.",
            "'+all' yerine '-all' (veya geçiş sürecinde '~all') kullanın.",
            SPF_REF,
        )]
    if "?all" in all_terms:
        return [_finding(
            "DNS-003", "SPF kaydı tarafsız (?all) sonlanıyor", Severity.MEDIUM, evidence,
            "'?all' listede olmayan sunucular için 'karar yok' der; pratikte sahte "
            "e-postaya karşı koruma sağlamaz.",
            "'?all' yerine '-all' veya '~all' kullanın.",
            SPF_REF,
        )]
    if not all_terms and not has_redirect:
        return [_finding(
            "DNS-003", "SPF kaydında 'all' kuralı yok", Severity.LOW, evidence,
            "'all' kuralı olmayan SPF kaydı, listede olmayan sunucular için varsayılan olarak "
            "'tarafsız' sonuç verir.",
            "Kaydın sonuna '-all' veya '~all' ekleyin.",
            SPF_REF,
        )]
    return []


def analyze_dmarc(domain: str, dmarc_records: list[str]) -> list[Finding]:
    records = [r.strip() for r in dmarc_records if r.strip().lower().startswith("v=dmarc1")]
    name = f"_dmarc.{domain}"
    if not records:
        return [_finding(
            "DNS-004", "DMARC kaydı bulunamadı", Severity.MEDIUM,
            f"{name} adresinde 'v=DMARC1' kaydı yok.",
            "DMARC, SPF/DKIM kontrolünden geçemeyen e-postaların reddedilmesini sağlar ve "
            "alan adı sahibine sahte e-posta raporları gönderir. Olmadığında sahte "
            "e-postalar alıcıya ulaşabilir.",
            "Raporlama ile başlayın: v=DMARC1; p=none; rua=mailto:dmarc@alanadiniz; "
            "sonra p=quarantine ve p=reject'e geçin.",
            DMARC_REF,
        )]
    if len(records) > 1:
        return [_finding(
            "DNS-005", "Birden fazla DMARC kaydı var", Severity.MEDIUM,
            f"{name}: " + " | ".join(records),
            "Birden fazla DMARC kaydı olduğunda alıcı sunucular DMARC'ı tamamen yok sayar.",
            "Tek bir DMARC kaydı bırakın.",
            DMARC_REF,
        )]

    tags = {}
    for part in records[0].split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip().lower()
    policy = tags.get("p", "")
    if policy == "none":
        return [_finding(
            "DNS-005", "DMARC politikası yalnızca izleme modunda (p=none)", Severity.LOW,
            f"{name}: {records[0]}",
            "p=none, başarısız e-postalar için hiçbir işlem yapılmamasını ister; yalnızca "
            "raporlama sağlar. Geçiş süreci için uygundur, kalıcı olmamalıdır.",
            "Raporları inceledikten sonra p=quarantine, ardından p=reject politikasına geçin.",
            DMARC_REF,
        )]
    if policy not in ("quarantine", "reject"):
        return [_finding(
            "DNS-005", "DMARC politikası geçersiz veya eksik", Severity.MEDIUM,
            f"{name}: {records[0]}",
            "Geçerli bir 'p=' etiketi olmayan DMARC kaydı alıcı sunucular tarafından yok sayılabilir.",
            "Kayda p=quarantine veya p=reject ekleyin.",
            DMARC_REF,
        )]
    return []


# ---------------------------------------------------------------------------
# Ağ işlemleri
# ---------------------------------------------------------------------------


# Yerel/özel kullanım için ayrılmış adlar: internet DNS'inde e-posta kayıtları olmaz
_LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".lan", ".home.arpa",
                   ".example", ".invalid")


def is_local_name(hostname: str) -> bool:
    """'localhost', 'sunucu' veya 'uygulama.test' gibi yerel adlar mı?"""
    return "." not in hostname or hostname == "localhost" or hostname.endswith(_LOCAL_SUFFIXES)


def _email_domain(hostname: str) -> str:
    return hostname[4:] if hostname.startswith("www.") else hostname


def check_dns(target: Target, *, resolve: Resolve = _default_resolve) -> CheckResult:
    """DNS kontrolünü çalıştırır. Hata fırlatmaz."""
    started = time.monotonic()

    def result(status, findings=None, message=None, details=None):
        return CheckResult(check_name=CHECK_NAME, status=status, findings=findings or [],
                           message=message, details=details or {},
                           duration_seconds=time.monotonic() - started)

    if target.is_ip:
        return result(CheckStatus.SKIPPED,
                      message="Hedef bir IP adresi olduğu için DNS kontrolleri uygulanamaz.")
    if is_local_name(target.hostname):
        return result(CheckStatus.SKIPPED,
                      message="Hedef yerel bir ad olduğu için internet DNS kontrolleri uygulanamaz.")

    failed: list[str] = []
    attempted: list[str] = []

    def lookup(name: str, rtype: str) -> list[str] | None:
        """Kayıtları döndürür. Kayıt yoksa [], sorgu başarısızsa None."""
        attempted.append(f"{name} {rtype}")
        try:
            return resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError):
            failed.append(f"{name} {rtype}")
            return None

    host = target.hostname
    domain = _email_domain(host)
    details: dict = {"email_domain": domain}
    findings: list[Finding] = []

    for rtype in ("A", "AAAA", "NS", "MX"):
        details[rtype.lower()] = lookup(domain if rtype in ("NS", "MX") else host, rtype)

    # --- E-posta güvenliği ------------------------------------------------
    txt = lookup(domain, "TXT")
    if txt is not None:
        details["spf"] = [r for r in txt if r.lower().startswith("v=spf1")]
        findings += analyze_spf(domain, txt)

    dmarc = lookup(f"_dmarc.{domain}", "TXT")
    if dmarc is not None:
        details["dmarc"] = [r for r in dmarc if r.lower().startswith("v=dmarc1")]
        findings += analyze_dmarc(domain, dmarc)

    # --- Ad sunucuları ----------------------------------------------------
    ns = details["ns"]
    if ns is not None and len(ns) == 1:
        findings.append(_finding(
            "DNS-009", "Tek bir ad sunucusu (NS) kullanılıyor", Severity.LOW,
            f"{domain} NS: {ns[0]}",
            "Tek ad sunucusu çalışmadığında alan adı tamamen erişilemez hale gelir.",
            "Farklı ağlarda en az iki ad sunucusu kullanın.",
            ["https://datatracker.ietf.org/doc/html/rfc2182"],
        ))

    # --- CAA: önce ana makine adı, bulunamazsa üst alan adı aranır --------
    caa_names = [host] if host == domain else [host, domain]
    caa: list[str] | None = []
    for name in caa_names:
        caa = lookup(name, "CAA")
        if caa:
            break
    details["caa"] = caa
    if caa == []:
        findings.append(_finding(
            "DNS-006", "CAA kaydı bulunamadı", Severity.INFO,
            f"{', '.join(caa_names)} için CAA kaydı yok.",
            "CAA kaydı, alan adınıza yalnızca belirlediğiniz sertifika otoritelerinin "
            "sertifika vermesine izin verir; yetkisiz sertifika riskini azaltır.",
            'Kullandığınız otoriteyi belirtin, ör: ornek.com. CAA 0 issue "letsencrypt.org"',
            CAA_REF,
        ))

    # --- DNSSEC -----------------------------------------------------------
    ds = lookup(domain, "DS")
    details["dnssec"] = None if ds is None else bool(ds)
    if ds == []:
        findings.append(_finding(
            "DNS-007", "DNSSEC etkin değil", Severity.INFO,
            f"{domain} için DS kaydı bulunamadı.",
            "DNSSEC, DNS yanıtlarının sahte yanıtlarla değiştirilmesini (DNS cache "
            "poisoning) önler. Birçok sitede henüz etkin değildir.",
            "Alan adı kayıt firmanız ve DNS sağlayıcınız destekliyorsa DNSSEC'i etkinleştirin.",
            DNSSEC_REF,
            confidence=Confidence.INFORMATIONAL,
        ))

    details["failed_queries"] = failed
    if failed and len(failed) == len(attempted):
        return result(CheckStatus.ERROR, message="DNS sorgularının tamamı başarısız oldu. "
                      "Ağ bağlantınızı veya DNS sunucunuzu kontrol edin.", details=details)

    message = None
    if failed:
        message = ("Bazı DNS sorguları başarısız oldu ve değerlendirilemedi: "
                   + ", ".join(failed) + ". Bu kayıtların eksik olduğu varsayılmamalıdır.")
    return result(CheckStatus.COMPLETED, findings, message, details)
