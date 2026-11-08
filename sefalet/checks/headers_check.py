"""HTTP güvenlik başlıkları analizi.

Bir web sunucusu her yanıtla birlikte "başlıklar" (headers) gönderir.
Bazı başlıklar tarayıcıya güvenlik talimatı verir; örneğin:
    Strict-Transport-Security → "Bu siteye her zaman HTTPS ile bağlan"
    Content-Security-Policy   → "Yalnızca şu kaynaklardan script çalıştır"

Önemli ilke: Eksik bir güvenlik başlığı tek başına bir "açık" DEĞİLDİR;
bir sağlamlaştırma (hardening) eksikliğidir. Bu yüzden risk seviyeleri
temkinli tutulmuştur ve açıklamalar bunu belirtir.

Modül iki parçadan oluşur:
    analyze_headers()  → Saf fonksiyon: başlıkları alır, bulgu listesi döndürür.
                         İnternete çıkmaz; test etmesi kolaydır.
    check_headers()    → Siteye bağlanır, yanıtı alır ve analyze_headers'ı çağırır.
"""

from __future__ import annotations

import re
import time
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from sefalet import config
from sefalet.models import CheckResult, CheckStatus, Confidence, Finding, Severity
from sefalet.target import Target

CHECK_NAME = "headers"
CATEGORY = "HTTP Güvenlik Başlıkları"
MAX_REDIRECTS = 5
HSTS_MIN_MAX_AGE = 15552000  # 180 gün (saniye)

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


class _Headers:
    """Büyük/küçük harf duyarsız başlık sözlüğü.

    HTTP başlık adları büyük/küçük harfe duyarsızdır:
    "content-security-policy" ile "Content-Security-Policy" aynıdır.
    """

    def __init__(self, headers: Mapping[str, str]) -> None:
        self._data = {k.lower(): v for k, v in headers.items()}

    def get(self, name: str) -> str | None:
        value = self._data.get(name.lower())
        return value.strip() if isinstance(value, str) else None


@dataclass
class Cookie:
    name: str
    attributes: set[str]  # küçük harfli öznitelik adları: {"secure", "httponly", "samesite"}


def parse_set_cookie(header_value: str) -> Cookie | None:
    """Tek bir Set-Cookie başlığını ayrıştırır.

    Örnek: "oturum=abc; Path=/; Secure; HttpOnly"
        → Cookie(name="oturum", attributes={"path", "secure", "httponly"})
    """
    parts = [p.strip() for p in header_value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    attributes = {p.split("=", 1)[0].strip().lower() for p in parts[1:] if p}
    return Cookie(name=name, attributes=attributes)


def _finding(id_: str, title: str, severity: Severity, evidence: str, description: str,
             recommendation: str, confidence: Confidence = Confidence.CONFIRMED,
             references: list[str] | None = None) -> Finding:
    """Bu modülün bulgularını aynı kategoriyle kısa yoldan oluşturur."""
    return Finding(
        id=id_, category=CATEGORY, title=title, severity=severity, confidence=confidence,
        evidence=evidence, description=description, recommendation=recommendation,
        references=references or [OWASP_HEADERS],
    )


def _csp_directives(csp: str) -> dict[str, str]:
    """CSP metnini {direktif: değer} sözlüğüne çevirir.

    "default-src 'self'; script-src 'self' cdn.com" →
        {"default-src": "'self'", "script-src": "'self' cdn.com"}
    """
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        tokens = part.strip().split(None, 1)
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1] if len(tokens) > 1 else "")
    return directives


# ---------------------------------------------------------------------------
# Analiz (saf fonksiyon, internete çıkmaz)
# ---------------------------------------------------------------------------


def analyze_headers(
    headers: Mapping[str, str],
    *,
    set_cookies: list[str] | None = None,
    is_https: bool = True,
    url: str = "",
) -> list[Finding]:
    """Yanıt başlıklarını inceler ve bulgu listesi döndürür.

    Args:
        headers: Yanıt başlıkları.
        set_cookies: Her Set-Cookie başlığı ayrı bir eleman olarak.
        is_https: Yanıt HTTPS üzerinden mi geldi? (HSTS ve Secure çerez kontrolleri için)
        url: Kanıt metinlerinde gösterilecek adres.
    """
    h = _Headers(headers)
    where = f" ({url})" if url else ""
    findings: list[Finding] = []

    # --- HSTS: yalnızca HTTPS yanıtında anlamlıdır ------------------------
    if is_https:
        findings.extend(_check_hsts(h.get("Strict-Transport-Security"), where))

    # --- CSP ve clickjacking -----------------------------------------------
    csp = h.get("Content-Security-Policy")
    directives = _csp_directives(csp) if csp else {}
    if not csp:
        findings.append(_finding(
            "HDR-004", "Content-Security-Policy başlığı bulunamadı", Severity.MEDIUM,
            f"Yanıtta Content-Security-Policy başlığı yok{where}.",
            "CSP, tarayıcının hangi kaynaklardan script/stil yükleyebileceğini sınırlar ve "
            "olası XSS (siteler arası betik) saldırılarının etkisini azaltır. Eksikliği "
            "tek başına bir açık değildir, ancak önemli bir savunma katmanının yokluğudur.",
            "Önce 'Content-Security-Policy-Report-Only' ile bir politika deneyin, ardından "
            "zorunlu hale getirin. Başlangıç: default-src 'self'; object-src 'none'; "
            "frame-ancestors 'self'",
            references=[OWASP_HEADERS, MDN + "Content-Security-Policy"],
        ))
    else:
        findings.extend(_check_csp_weaknesses(directives, where))

    xfo = h.get("X-Frame-Options")
    if not xfo and "frame-ancestors" not in directives:
        findings.append(_finding(
            "HDR-006", "Clickjacking koruması bulunamadı", Severity.MEDIUM,
            f"X-Frame-Options başlığı ve CSP frame-ancestors direktifi yok{where}.",
            "Sayfa başka bir sitenin içinde görünmez bir çerçeveye (iframe) yerleştirilebilir. "
            "Saldırgan, kullanıcıyı farkında olmadan butonlara tıklatabilir (clickjacking). "
            "Gerçek etkisi sayfada önemli işlem olup olmamasına bağlıdır.",
            "CSP'ye frame-ancestors 'self' ekleyin veya X-Frame-Options: DENY / SAMEORIGIN gönderin.",
            references=[OWASP_HEADERS, MDN + "X-Frame-Options"],
        ))

    # --- Diğer başlıklar ---------------------------------------------------
    xcto = h.get("X-Content-Type-Options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append(_finding(
            "HDR-007", "X-Content-Type-Options: nosniff ayarlanmamış", Severity.LOW,
            f"X-Content-Type-Options değeri: {xcto or 'yok'}{where}.",
            "Tarayıcı, dosya türünü içeriğe bakarak tahmin edebilir (MIME sniffing); bu da "
            "yüklenen bir dosyanın script olarak çalıştırılmasına yol açabilir.",
            "X-Content-Type-Options: nosniff başlığını gönderin.",
        ))

    if not h.get("Referrer-Policy"):
        findings.append(_finding(
            "HDR-008", "Referrer-Policy başlığı bulunamadı", Severity.INFO,
            f"Yanıtta Referrer-Policy başlığı yok{where}.",
            "Güncel tarayıcılar varsayılan olarak 'strict-origin-when-cross-origin' kullanır; "
            "yine de politikanın açıkça belirtilmesi eski tarayıcılarda adres bilgisinin "
            "(URL'deki parametreler dahil) başka sitelere sızmasını önler.",
            "Referrer-Policy: strict-origin-when-cross-origin başlığını gönderin.",
        ))

    if not h.get("Permissions-Policy"):
        findings.append(_finding(
            "HDR-009", "Permissions-Policy başlığı bulunamadı", Severity.INFO,
            f"Yanıtta Permissions-Policy başlığı yok{where}.",
            "Bu başlık kamera, mikrofon, konum gibi tarayıcı özelliklerinin sayfada "
            "kullanımını kısıtlar. Kullanılmayan özelliklerin kapatılması önerilir.",
            "Örnek: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ))

    # --- Sürüm bilgisi sızıntısı -------------------------------------------
    server = h.get("Server")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(_finding(
            "HDR-011", "Sunucu yazılım sürümü açıkça gösteriliyor", Severity.LOW,
            f"Server: {server}{where}",
            "Sürüm bilgisi, saldırganın bilinen açıkları hedeflemesini kolaylaştırır. "
            "Bu tarama, belirtilen sürümde gerçekten bir açık olup olmadığını doğrulamaz.",
            "Sunucu yapılandırmasında sürüm bilgisini gizleyin "
            "(ör. nginx: server_tokens off; Apache: ServerTokens Prod).",
        ))

    disclosed = [f"{name}: {h.get(name)}" for name in
                 ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version") if h.get(name)]
    if disclosed:
        findings.append(_finding(
            "HDR-012", "Uygulama altyapısı başlıklarda gösteriliyor", Severity.LOW,
            "; ".join(disclosed) + where,
            "Kullanılan dil/çatı ve sürüm bilgisi saldırgana keşif kolaylığı sağlar.",
            "Bu başlıkları sunucu veya uygulama yapılandırmasından kaldırın "
            "(ör. PHP: expose_php = Off).",
        ))

    # --- CORS --------------------------------------------------------------
    acao = h.get("Access-Control-Allow-Origin")
    acac = (h.get("Access-Control-Allow-Credentials") or "").lower()
    if acao == "*" and acac == "true":
        findings.append(_finding(
            "HDR-017", "CORS yapılandırması hatalı görünüyor", Severity.MEDIUM,
            f"Access-Control-Allow-Origin: * ve Access-Control-Allow-Credentials: true{where}.",
            "Bu kombinasyon tarayıcılar tarafından reddedilir; genellikle yanlış bir CORS "
            "yapılandırmasının belirtisidir. Sunucu farklı isteklerde Origin değerini "
            "yansıtıyor olabilir; bu durumun manuel olarak doğrulanması gerekir.",
            "Yalnızca güvenilen alan adlarını açıkça listeleyin.",
            confidence=Confidence.PROBABLE,
        ))

    # --- Çerezler ----------------------------------------------------------
    findings.extend(_check_cookies(set_cookies or [], is_https, where))
    return findings


def _check_hsts(hsts: str | None, where: str) -> list[Finding]:
    refs = [OWASP_HEADERS, MDN + "Strict-Transport-Security"]
    if not hsts:
        return [_finding(
            "HDR-001", "HSTS (Strict-Transport-Security) başlığı bulunamadı", Severity.MEDIUM,
            f"HTTPS yanıtında Strict-Transport-Security başlığı yok{where}.",
            "HSTS olmadan, kullanıcının siteye ilk bağlantısı HTTP üzerinden yapılabilir ve "
            "ağdaki bir saldırgan bağlantıyı şifresiz hale düşürebilir (SSL stripping).",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains başlığını gönderin.",
            references=refs,
        )]

    findings: list[Finding] = []
    match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_MIN_MAX_AGE:
        findings.append(_finding(
            "HDR-002", "HSTS süresi kısa", Severity.LOW,
            f"Strict-Transport-Security: {hsts}{where}",
            f"max-age değeri {max_age} saniye. 180 günden ({HSTS_MIN_MAX_AGE} sn) kısa "
            "süreler korumanın sık sık sona ermesine yol açar. max-age=0 HSTS'yi kapatır.",
            "max-age değerini en az 31536000 (1 yıl) yapın.",
            references=refs,
        ))
    if "includesubdomains" not in hsts.lower():
        findings.append(_finding(
            "HDR-003", "HSTS alt alan adlarını kapsamıyor", Severity.INFO,
            f"Strict-Transport-Security: {hsts}{where}",
            "includeSubDomains olmadan alt alan adları HSTS korumasından yararlanmaz.",
            "Tüm alt alan adları HTTPS destekliyorsa includeSubDomains ekleyin.",
            references=refs,
        ))
    return findings


def _check_csp_weaknesses(directives: dict[str, str], where: str) -> list[Finding]:
    # Script kuralı yoksa default-src geçerlidir
    script_policy = directives.get("script-src", directives.get("default-src"))
    if script_policy is None:
        return [_finding(
            "HDR-005", "CSP script kaynaklarını sınırlamıyor", Severity.LOW,
            f"CSP'de script-src veya default-src direktifi yok{where}.",
            "Politika mevcut ancak script kaynaklarına bir sınır koymadığı için XSS'e "
            "karşı koruma sağlamaz.",
            "script-src veya default-src direktifi ekleyin.",
        )]
    weak = [kw for kw in ("'unsafe-inline'", "'unsafe-eval'") if kw in script_policy.lower()]
    # Nonce veya hash varsa modern tarayıcılar 'unsafe-inline'ı yok sayar
    if "'unsafe-inline'" in weak and re.search(r"'(nonce-|sha256-|sha384-|sha512-)", script_policy):
        weak.remove("'unsafe-inline'")
    if not weak:
        return []
    return [_finding(
        "HDR-005", "CSP güvensiz script kaynaklarına izin veriyor", Severity.LOW,
        f"Script politikası şunları içeriyor: {', '.join(weak)}{where}.",
        "'unsafe-inline' ve 'unsafe-eval', CSP'nin XSS'e karşı sağladığı korumayı büyük "
        "ölçüde ortadan kaldırır.",
        "Satır içi scriptler için nonce veya hash kullanın; eval kullanımını kaldırın.",
    )]


def _check_cookies(set_cookies: list[str], is_https: bool, where: str) -> list[Finding]:
    cookies = [c for c in (parse_set_cookie(v) for v in set_cookies) if c]
    if not cookies:
        return []

    def names(items: list[Cookie]) -> str:
        return ", ".join(sorted({c.name for c in items}))

    findings: list[Finding] = []
    no_secure = [c for c in cookies if "secure" not in c.attributes]
    if is_https and no_secure:
        findings.append(_finding(
            "HDR-013", "Secure bayrağı olmayan çerezler", Severity.LOW,
            f"Secure bayrağı eksik çerezler: {names(no_secure)}{where}",
            "Secure bayrağı olmayan çerezler şifresiz HTTP bağlantılarında da gönderilebilir. "
            "Çerez oturum bilgisi taşıyorsa risk artar; çerezin amacı manuel olarak "
            "doğrulanmalıdır.",
            "Tüm çerezlere Secure bayrağı ekleyin.",
        ))
    no_httponly = [c for c in cookies if "httponly" not in c.attributes]
    if no_httponly:
        findings.append(_finding(
            "HDR-014", "HttpOnly bayrağı olmayan çerezler", Severity.LOW,
            f"HttpOnly bayrağı eksik çerezler: {names(no_httponly)}{where}",
            "HttpOnly olmayan çerezler JavaScript ile okunabilir; bir XSS açığı varsa "
            "çalınabilir. Bazı çerezlerin (ör. arayüz tercihleri) JavaScript erişimine "
            "bilinçli olarak açık olması normaldir.",
            "Oturum ve kimlik doğrulama çerezlerine HttpOnly bayrağı ekleyin.",
            confidence=Confidence.PROBABLE,
        ))
    no_samesite = [c for c in cookies if "samesite" not in c.attributes]
    if no_samesite:
        findings.append(_finding(
            "HDR-015", "SameSite özniteliği olmayan çerezler", Severity.INFO,
            f"SameSite özniteliği eksik çerezler: {names(no_samesite)}{where}",
            "Güncel tarayıcılar SameSite belirtilmemiş çerezleri 'Lax' kabul eder; açıkça "
            "belirtmek tutarlı davranış ve CSRF'e karşı ek koruma sağlar.",
            "Çerezlere SameSite=Lax (veya uygunsa Strict) ekleyin.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Ağ: siteye bağlanma
# ---------------------------------------------------------------------------


def _same_site(url: str, hostname: str) -> bool:
    """Yönlendirme hedefi aynı site mi? (ornek.com ↔ www.ornek.com dahil)"""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host in (hostname, f"www.{hostname}") or f"www.{host}" == hostname


def _get(url: str, verify: bool = True) -> requests.Response:
    """Yönlendirme takip etmeden GET isteği yapar; gövdeyi indirmez.

    verify=False yalnızca lab modunda kullanılır (kendi test ortamındaki
    kendinden imzalı sertifikalar için).
    """
    response = requests.get(
        url, timeout=config.HTTP_TIMEOUT, allow_redirects=False, stream=True,
        headers={"User-Agent": config.USER_AGENT}, verify=verify,
    )
    response.close()  # Yalnızca başlıklar lazım; gövdeyi indirmiyoruz
    return response


def _set_cookie_list(response: requests.Response) -> list[str]:
    """Set-Cookie başlıklarını ayrı ayrı döndürür.

    `response.headers` birden fazla Set-Cookie'yi virgülle birleştirir; tarih
    alanlarında da virgül olduğundan bu ayrıştırmayı bozar. Bu yüzden ham
    başlıklardan liste olarak okuyoruz.
    """
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _fetch_final(target: Target, verify: bool = True) -> tuple[requests.Response, str, list[Finding]]:
    """Ana sayfayı alır; yalnızca aynı sitedeki yönlendirmeleri takip eder.

    Başka bir siteye yönlendirmeler takip edilmez: hem izin kapsamı dışıdır,
    hem de iç ağ adreslerine yönlendirme (SSRF) riski taşır.
    """
    url = target.base_url
    notes: list[Finding] = []
    response = _get(url, verify)
    for _ in range(MAX_REDIRECTS):
        location = response.headers.get("Location")
        if not (response.is_redirect and location):
            break
        next_url = urljoin(url, location)
        if not _same_site(next_url, target.hostname):
            notes.append(_finding(
                "HDR-016", "Site başka bir alan adına yönlendiriyor", Severity.INFO,
                f"{url} → {next_url}",
                "Yönlendirme hedefi tarama kapsamı dışında olduğu için takip edilmedi. "
                "Başlıklar yönlendirme yanıtına göre değerlendirildi.",
                "Hedef site sizinse, o alan adı için ayrı tarama başlatın.",
                confidence=Confidence.INFORMATIONAL,
            ))
            break
        if urlsplit(url).scheme == "https" and urlsplit(next_url).scheme == "http":
            notes.append(_finding(
                "HDR-018", "HTTPS bağlantısı HTTP'ye yönlendiriliyor", Severity.MEDIUM,
                f"{url} → {next_url}",
                "Şifreli bağlantı şifresiz bağlantıya düşürülüyor; aktarılan veriler ağda "
                "okunabilir hale gelir.",
                "Tüm yönlendirmelerin HTTPS adreslerine yapıldığından emin olun.",
            ))
        url = next_url
        response = _get(url, verify)
    return response, url, notes


def _check_http_to_https(target: Target) -> list[Finding]:
    """http://site/ adresinin HTTPS'e yönlendirilip yönlendirilmediğini kontrol eder."""
    if target.scheme != "https" or target.port != 443:
        return []
    host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    http_url = f"http://{host}/"
    try:
        response = _get(http_url)
    except requests.exceptions.RequestException:
        return []  # 80 portu kapalıysa HTTP zaten sunulmuyor demektir: sorun yok

    location = response.headers.get("Location", "")
    if response.is_redirect and urljoin(http_url, location).startswith("https://"):
        return []
    return [_finding(
        "HDR-010", "HTTP istekleri HTTPS'e yönlendirilmiyor", Severity.MEDIUM,
        f"{http_url} → HTTP {response.status_code}"
        + (f", Location: {location}" if location else ""),
        "Site şifresiz HTTP üzerinden de erişilebilir durumda. Kullanıcılar adresi "
        "'http://' ile yazdığında bağlantı şifrelenmez.",
        "Tüm HTTP isteklerini kalıcı (301) yönlendirme ile HTTPS'e yönlendirin.",
    )]


def check_headers(target: Target) -> CheckResult:
    """HTTP güvenlik başlıkları kontrolünü çalıştırır. Hata fırlatmaz."""
    started = time.monotonic()
    # Lab modunda (kullanıcının kendi yerel ortamı) kendinden imzalı sertifikalar
    # yaygındır; başlıkları okuyabilmek için sertifika doğrulaması atlanır.
    # Sertifika sorunu TLS kontrolünde ayrıca raporlanır.
    verify = not target.lab_mode

    def result(status: CheckStatus, findings: list[Finding], message: str | None = None):
        return CheckResult(check_name=CHECK_NAME, status=status, findings=findings,
                           message=message, duration_seconds=time.monotonic() - started)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            response, final_url, findings = _fetch_final(target, verify)
    except requests.exceptions.SSLError:
        return result(CheckStatus.ERROR, [],
                      "HTTPS sertifikası doğrulanamadığı için başlıklar okunamadı. "
                      "Ayrıntılar için TLS kontrolü bulgularına bakın.")
    except requests.exceptions.Timeout:
        return result(CheckStatus.ERROR, [], f"Sunucu zamanında yanıt vermedi: {target.base_url}")
    except requests.exceptions.ConnectionError:
        return result(CheckStatus.ERROR, [], f"Sunucuya bağlanılamadı: {target.base_url}")
    except requests.exceptions.RequestException as exc:
        return result(CheckStatus.ERROR, [], f"HTTP isteği başarısız: {exc}")

    findings += analyze_headers(
        response.headers,
        set_cookies=_set_cookie_list(response),
        is_https=final_url.startswith("https://"),
        url=final_url,
    )
    findings += _check_http_to_https(target)

    notes = []
    if not verify:
        notes.append("Lab modu: başlıklar okunurken sertifika doğrulaması atlandı.")
    if response.status_code >= 400:
        notes.append(f"Sunucu HTTP {response.status_code} döndürdü; başlıklar bu yanıta göre "
                     "değerlendirildi. Uygulama sayfalarında başlıklar farklı olabilir.")
    message = " ".join(notes) or None
    return result(CheckStatus.COMPLETED, findings, message)
