"""SSL/TLS sertifika ve protokol kontrolü.

HTTPS, tarayıcı ile sunucu arasındaki trafiği TLS protokolüyle şifreler.
Sunucu kimliğini bir "sertifika" ile kanıtlar. Bu modül şunlara bakar:

    Sertifika:
      - Süresi dolmuş mu / yakında doluyor mu?
      - Alan adıyla eşleşiyor mu?
      - Güvenilir bir sertifika otoritesi (CA) tarafından mı imzalanmış?
      - Anahtar yeterince güçlü mü? İmza algoritması eski mi (SHA-1)?
    Protokol:
      - Eski ve güvensiz TLS 1.0 / 1.1 kabul ediliyor mu?
      - Modern TLS 1.3 destekleniyor mu?

Bağlantılar her zaman target.py'nin çözümlediği IP'ye yapılır (DNS rebinding
koruması); alan adı yalnızca SNI ile sunucuya bildirilir.

Önemli: Kali'deki modern OpenSSL, TLS 1.0/1.1 bağlantısını bizim tarafımızda
reddedebilir. Bu durumda sonucu "desteklenmiyor" diye DEĞİL, "test edilemedi"
diye raporlarız. Yanlış güven vermek, yanlış alarm vermek kadar kötüdür.
"""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from sefalet import config
from sefalet.models import CheckResult, CheckStatus, Confidence, Finding, Severity
from sefalet.target import Target

CHECK_NAME = "tls"
CATEGORY = "SSL/TLS"
MOZILLA_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS"

EXPIRY_WARNING_DAYS = 14
EXPIRY_NOTICE_DAYS = 30
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

# OpenSSL doğrulama hata kodları (X509_V_ERR_*)
_EXPIRY_CODES = {9, 10}            # henüz geçerli değil / süresi dolmuş (kendimiz kontrol ediyoruz)
_HOSTNAME_CODES = {62, 64}         # ad / IP uyuşmazlığı (kendimiz kontrol ediyoruz)
_SELF_SIGNED_CODES = {18, 19}      # kendinden imzalı sertifika / zincirde kendinden imzalı

# Hatanın BİZİM tarafımızda (yerel OpenSSL) olduğunu gösteren nedenler
_LOCAL_SSL_REASONS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_SUITABLE_SIGNATURE_ALGORITHM"}

# Sonuç sabitleri
SUPPORTED = "destekleniyor"
NOT_SUPPORTED = "desteklenmiyor"
UNTESTED = "test edilemedi"

_DISPLAY_NAMES = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}


def _finding(id_: str, title: str, severity: Severity, evidence: str, description: str,
             recommendation: str, confidence: Confidence = Confidence.CONFIRMED) -> Finding:
    return Finding(id=id_, category=CATEGORY, title=title, severity=severity,
                   confidence=confidence, evidence=evidence, description=description,
                   recommendation=recommendation, references=[MOZILLA_TLS])


# ---------------------------------------------------------------------------
# Sertifika analizi (saf fonksiyonlar)
# ---------------------------------------------------------------------------


def _common_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def _organization(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return str(attrs[0].value) if attrs else ""


def certificate_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """Sertifikanın geçerli olduğu alan adları ve IP adresleri (SAN uzantısı)."""
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return [], []
    dns_names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return dns_names, ip_names


def hostname_matches(hostname: str, pattern: str) -> bool:
    """Alan adı sertifikadaki bir adla eşleşiyor mu?

    Joker karakter (*) yalnızca en soldaki bölümde ve tek bir bölüm yerine geçer:
        *.ornek.com  →  www.ornek.com ✓   ornek.com ✗   a.b.ornek.com ✗
    """
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if not pattern.startswith("*."):
        return hostname == pattern
    suffix = pattern[1:]  # ".ornek.com"
    if not hostname.endswith(suffix):
        return False
    label = hostname[: -len(suffix)]
    return bool(label) and "." not in label


def analyze_certificate(
    cert: x509.Certificate,
    hostname: str,
    *,
    is_ip: bool = False,
    now: datetime | None = None,
) -> tuple[list[Finding], dict]:
    """Sertifikayı inceler. (bulgular, rapor ayrıntıları) döndürür."""
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days
    dns_names, ip_names = certificate_names(cert)

    details = {
        "subject": _common_name(cert.subject),
        "issuer": _common_name(cert.issuer) or _organization(cert.issuer),
        "issuer_organization": _organization(cert.issuer),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "san": (dns_names + ip_names)[:20],
        "serial": format(cert.serial_number, "x"),
    }

    # --- Geçerlilik süresi --------------------------------------------------
    expiry_text = f"Bitiş tarihi: {not_after:%Y-%m-%d %H:%M} UTC"
    if now > not_after:
        findings.append(_finding(
            "TLS-001", "Sertifikanın süresi dolmuş", Severity.HIGH,
            f"{expiry_text} ({-days_left} gün önce).",
            "Tarayıcılar süresi dolmuş sertifikaya sahip sitelerde güvenlik uyarısı gösterir "
            "ve bağlantıyı engeller. Kullanıcılar uyarıları geçmeye alıştırılmış olur.",
            "Sertifikayı hemen yenileyin ve otomatik yenileme kurun (ör. Let's Encrypt + certbot).",
        ))
    elif days_left < EXPIRY_WARNING_DAYS:
        findings.append(_finding(
            "TLS-002", f"Sertifika {EXPIRY_WARNING_DAYS} gün içinde sona eriyor", Severity.MEDIUM,
            f"{expiry_text} ({days_left} gün kaldı).",
            "Sertifika yenilenmezse site kısa süre içinde erişilemez hale gelecek.",
            "Sertifikayı yenileyin ve otomatik yenilemenin çalıştığını doğrulayın.",
        ))
    elif days_left < EXPIRY_NOTICE_DAYS:
        findings.append(_finding(
            "TLS-002", f"Sertifika {EXPIRY_NOTICE_DAYS} gün içinde sona eriyor", Severity.LOW,
            f"{expiry_text} ({days_left} gün kaldı).",
            "Otomatik yenileme kullanılıyorsa bu normal olabilir; kullanılmıyorsa yenileme "
            "planlanmalıdır.",
            "Otomatik yenilemenin çalıştığını doğrulayın.",
        ))
    if now < not_before:
        findings.append(_finding(
            "TLS-006", "Sertifika henüz geçerli değil", Severity.HIGH,
            f"Başlangıç tarihi: {not_before:%Y-%m-%d %H:%M} UTC.",
            "Sertifikanın geçerlilik başlangıcı gelecekte. Sunucu saati veya sertifika hatalı olabilir.",
            "Sunucu saatini (NTP) ve sertifikayı kontrol edin.",
        ))

    # --- Alan adı eşleşmesi -------------------------------------------------
    if is_ip:
        name_ok = hostname in ip_names
    else:
        # SAN yoksa eski usul CN'ye bakılır (modern tarayıcılar CN'yi kabul etmez)
        patterns = dns_names or ([details["subject"].lower()] if details["subject"] else [])
        name_ok = any(hostname_matches(hostname, p) for p in patterns)
    if not name_ok:
        shown = ", ".join(details["san"][:5]) or details["subject"] or "yok"
        findings.append(_finding(
            "TLS-003", "Sertifika alan adıyla eşleşmiyor", Severity.HIGH,
            f"Hedef: {hostname}. Sertifikadaki adlar: {shown}.",
            "Tarayıcılar bu sertifikayı reddeder. Yanlış sertifika yüklenmiş veya sunucu "
            "farklı bir site için yapılandırılmış olabilir.",
            "Hedef alan adını kapsayan bir sertifika yükleyin.",
        ))

    # --- Anahtar gücü --------------------------------------------------------
    key = cert.public_key()
    weak_key = None
    if isinstance(key, rsa.RSAPublicKey):
        details["key"] = f"RSA {key.key_size} bit"
        if key.key_size < MIN_RSA_BITS:
            weak_key = f"RSA {key.key_size} bit (en az {MIN_RSA_BITS} önerilir)"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        details["key"] = f"EC {key.curve.name} ({key.curve.key_size} bit)"
        if key.curve.key_size < MIN_EC_BITS:
            weak_key = f"EC {key.curve.key_size} bit (en az {MIN_EC_BITS} önerilir)"
    elif isinstance(key, dsa.DSAPublicKey):
        details["key"] = f"DSA {key.key_size} bit"
        weak_key = "DSA anahtarı (artık önerilmiyor)"
    else:
        details["key"] = type(key).__name__.replace("PublicKey", "")
    if weak_key:
        findings.append(_finding(
            "TLS-007", "Sertifika anahtarı zayıf", Severity.HIGH, f"Anahtar: {weak_key}.",
            "Zayıf anahtarlar yeterli kaynağa sahip bir saldırgan tarafından kırılabilir.",
            "En az 2048 bit RSA veya 256 bit ECDSA anahtarla yeni sertifika oluşturun.",
        ))

    # --- İmza algoritması ---------------------------------------------------
    hash_alg = cert.signature_hash_algorithm
    details["signature_algorithm"] = hash_alg.name if hash_alg else "yok (ör. Ed25519)"
    is_self_signed = cert.issuer == cert.subject
    if hash_alg and hash_alg.name in ("sha1", "md5") and not is_self_signed:
        findings.append(_finding(
            "TLS-008", "Sertifika eski bir imza algoritması kullanıyor", Severity.MEDIUM,
            f"İmza algoritması: {hash_alg.name.upper()}.",
            "SHA-1 ve MD5'e karşı pratik çakışma saldırıları bilinmektedir; tarayıcılar "
            "bu sertifikaları reddeder.",
            "SHA-256 veya daha güçlü bir algoritmayla imzalanmış sertifika alın.",
        ))

    return findings, details


def classify_verify_error(code: int, message: str) -> Finding | None:
    """OpenSSL doğrulama hatasını bulguya çevirir.

    Süre ve alan adı hatalarını kendimiz ayrıntılı kontrol ettiğimiz için
    burada tekrar raporlamıyoruz.
    """
    if code in _EXPIRY_CODES or code in _HOSTNAME_CODES:
        return None
    if code in _SELF_SIGNED_CODES:
        title = "Sertifika kendinden imzalı (self-signed)"
        description = ("Sertifika güvenilir bir sertifika otoritesi tarafından imzalanmamış. "
                       "Tarayıcılar uyarı gösterir ve bağlantı, araya giren bir saldırgana "
                       "karşı korunmaz.")
    else:
        title = "Sertifika zinciri doğrulanamadı"
        description = ("Sertifika güvenilir bir otoriteye kadar doğrulanamadı. Ara sertifika "
                       "(intermediate) eksik olabilir veya imzalayan otorite güvenilir değildir.")
    return _finding(
        "TLS-004", title, Severity.HIGH, f"OpenSSL doğrulama hatası {code}: {message}.",
        description,
        "Güvenilir bir otoriteden sertifika alın ve sunucuya tam sertifika zincirini "
        "(fullchain) yükleyin.",
    )


def analyze_protocols(negotiated: str | None, legacy: dict[str, str]) -> list[Finding]:
    """TLS sürüm sonuçlarını bulguya çevirir.

    Args:
        negotiated: Varsayılan ayarlarla anlaşılan sürüm (ör. "TLSv1.3").
        legacy: {"TLSv1": SUPPORTED/NOT_SUPPORTED/UNTESTED, "TLSv1.1": ...}
    """
    findings: list[Finding] = []
    supported_old = [v for v, status in legacy.items() if status == SUPPORTED]
    if supported_old:
        names = ", ".join(_DISPLAY_NAMES.get(v, v) for v in supported_old)
        findings.append(_finding(
            "TLS-009", "Eski TLS sürümleri destekleniyor", Severity.MEDIUM,
            f"Sunucu şu sürümlerle bağlantı kabul etti: {names}.",
            "TLS 1.0 ve 1.1 resmi olarak kullanımdan kaldırılmıştır (RFC 8996) ve bilinen "
            "zayıflıklar içerir. PCI DSS gibi standartlar bu sürümleri yasaklar.",
            "Sunucuda yalnızca TLS 1.2 ve TLS 1.3'ü etkinleştirin.",
        ))
    if negotiated and negotiated != "TLSv1.3":
        findings.append(_finding(
            "TLS-010", "TLS 1.3 desteklenmiyor", Severity.INFO,
            f"Anlaşılan en yüksek sürüm: {negotiated}.",
            "TLS 1.3 daha hızlı bağlantı kurar ve eski, zayıf şifreleme yöntemlerini kaldırır.",
            "Sunucu yazılımını güncelleyip TLS 1.3'ü etkinleştirin.",
            confidence=Confidence.PROBABLE,
        ))
    return findings


# ---------------------------------------------------------------------------
# Ağ işlemleri
# ---------------------------------------------------------------------------


def _connect(target: Target, context: ssl.SSLContext) -> ssl.SSLSocket:
    """Çözümlenmiş IP'ye bağlanır ve TLS el sıkışmasını yapar."""
    sock = socket.create_connection((target.primary_ip, target.port), timeout=config.TLS_TIMEOUT)
    try:
        return context.wrap_socket(sock, server_hostname=target.hostname)
    except BaseException:
        sock.close()
        raise


def _unverified_context() -> ssl.SSLContext:
    """Sertifikayı doğrulamadan bağlanan bağlam.

    Sertifikayı OKUMAK için kullanılır; geçersiz sertifikaları da inceleyebilmek
    için doğrulamayı burada kapatıyoruz. Doğrulamayı ayrıca yapıyoruz.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _verify_chain(target: Target, ca_file: str | None = None) -> Finding | None:
    """Sertifika zincirinin güvenilir olup olmadığını kontrol eder."""
    context = ssl.create_default_context(cafile=ca_file)
    context.check_hostname = False  # Ad kontrolünü analyze_certificate yapıyor
    try:
        with _connect(target, context):
            return None
    except ssl.SSLCertVerificationError as exc:
        return classify_verify_error(exc.verify_code, exc.verify_message)


def probe_version(target: Target, version: ssl.TLSVersion) -> str:
    """Sunucunun belirli bir TLS sürümünü kabul edip etmediğini dener."""
    context = _unverified_context()
    try:
        with warnings.catch_warnings():  # Python, eski sürümler için uyarı verir
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        context.set_ciphers("ALL:@SECLEVEL=0")  # Eski sürümler eski şifreler gerektirir
    except (ValueError, ssl.SSLError):
        return UNTESTED  # Yerel OpenSSL bu sürümü hiç desteklemiyor

    try:
        with _connect(target, context) as ssock:
            return SUPPORTED if ssock.version() == _VERSION_NAMES[version] else NOT_SUPPORTED
    except ssl.SSLError as exc:
        if getattr(exc, "reason", None) in _LOCAL_SSL_REASONS:
            return UNTESTED
        return NOT_SUPPORTED  # Sunucu el sıkışmayı reddetti
    except OSError:
        return UNTESTED  # Bağlantı sorunu: sonuç bilinmiyor


_VERSION_NAMES = {ssl.TLSVersion.TLSv1: "TLSv1", ssl.TLSVersion.TLSv1_1: "TLSv1.1"}


def check_tls(target: Target, *, ca_file: str | None = None) -> CheckResult:
    """TLS kontrolünü çalıştırır. Hata fırlatmaz.

    Args:
        ca_file: Güvenilir CA dosyası (testler için; normalde sistem CA'ları kullanılır).
    """
    started = time.monotonic()

    def result(status, findings=None, message=None, details=None):
        return CheckResult(check_name=CHECK_NAME, status=status, findings=findings or [],
                           message=message, details=details or {},
                           duration_seconds=time.monotonic() - started)

    if target.scheme != "https":
        return result(CheckStatus.SKIPPED,
                      message="Hedef HTTP olarak verildi; TLS kontrolü için hedefi https:// ile verin.")

    # 1) Sertifikayı ve anlaşılan sürümü oku
    try:
        with _connect(target, _unverified_context()) as ssock:
            der = ssock.getpeercert(binary_form=True)
            negotiated = ssock.version()
            cipher = ssock.cipher()
    except (TimeoutError, socket.timeout):
        return result(CheckStatus.ERROR,
                      message=f"{target.primary_ip}:{target.port} adresine bağlantı zaman aşımına uğradı.")
    except ConnectionRefusedError:
        return result(CheckStatus.ERROR,
                      message=f"{target.primary_ip}:{target.port} bağlantıyı reddetti; HTTPS sunulmuyor olabilir.")
    except ssl.SSLError as exc:
        return result(CheckStatus.ERROR, message=f"TLS el sıkışması başarısız: {exc.reason or exc}.")
    except OSError as exc:
        return result(CheckStatus.ERROR, message=f"Bağlantı hatası: {exc}.")

    if not der:
        return result(CheckStatus.ERROR, message="Sunucu sertifika göndermedi.")

    try:
        cert = x509.load_der_x509_certificate(der)
        findings, details = analyze_certificate(cert, target.hostname, is_ip=target.is_ip)
    except ValueError as exc:
        return result(CheckStatus.ERROR, message=f"Sertifika ayrıştırılamadı: {exc}.")

    details["protocol"] = negotiated
    details["cipher"] = cipher[0] if cipher else None

    # 2) Güven zinciri
    try:
        chain_finding = _verify_chain(target, ca_file)
    except (ssl.SSLError, OSError) as exc:
        chain_finding = None
        details["chain_check"] = f"{UNTESTED}: {exc}"
    if chain_finding:
        findings.append(chain_finding)

    # 3) Eski protokoller
    legacy = {name: probe_version(target, version) for version, name in _VERSION_NAMES.items()}
    details["legacy_protocols"] = legacy
    findings += analyze_protocols(negotiated, legacy)

    message = None
    if UNTESTED in legacy.values():
        message = ("Bazı eski TLS sürümleri bu sistemde test edilemedi (yerel OpenSSL "
                   "desteklemiyor veya bağlantı kurulamadı). Bu sürümlerin sunucuda "
                   "kapalı olduğu varsayılmamalıdır.")
    return result(CheckStatus.COMPLETED, findings, message, details)
